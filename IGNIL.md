# IGNIL — Implementation Guide

IGNIL (IGNIS Intermediate Language) is dragon-tales' lightweight IL for
architecture-specific analyses. It sits between raw disassembly and
heavyweight IRs like LLVM IR. The design follows conventions established
by VEX IR (angr/Valgrind), P-CODE (Ghidra), and BAP's BIL.

> **This is a historical build log, not a current reference.** It was
> written incrementally, step by step, as IGNIL and its surrounding
> analyses were first built, and reads that way (including include paths
> like `dragon/IGNIL.hpp` that no longer match the real tree, e.g.
> `dragon/lifters/ignil/IGNIL.hpp`). It's kept for the design rationale
> behind decisions that aren't obvious from the code alone. For the
> current, accurate API surface, use [`docs/cpp_api.md`](docs/cpp_api.md)
> (and `docs/c_api.md`/`docs/python_api.md` for the other two layers)
> instead.

---

## Design decisions already made

| Topic | Decision | Rationale |
|---|---|---|
| Value representation | `std::variant<Const, Reg, Temp>` | Fixed set, value semantics, no heap per value |
| Signedness | In the opcode, not the type | Convention from VEX, P-CODE, LLVM IR |
| Floatness | In the opcode too - a `Const`/`Reg`/`Temp`'s bits are reinterpreted as `double` only by an `FADD`/`FSUB`/`FMUL`/`FDIV`/`SITOFP`/`FPTOSI` | Same rationale as signedness - no second `Value` variant, no type tag |
| Register model | Offset + width in a register space | Handles sub-registers (EAX/RAX) naturally |
| Temporaries | Per-block unique `uint32_t` id | SSA-style, no cross-block aliasing |
| Block ownership | `Block` owns its `Op` sequence | Matches VEX IRSB, enables per-block analysis |
| Instruction markers | None (address on every `Op`) | Redundant given address field |
| Storage in graph | `std::map<uint64_t, ignil::Block>` | Same pattern as `listing_` |

---

## Part 1 — Implementing IGNIL types

### Step 1 — Create `include/dragon/IGNIL.hpp`

This is the public header. Everything lives in `namespace dragon::ignil`.

#### 1a. Width alias

```cpp
using Width = std::uint8_t;  // bit width: 1, 8, 16, 32, 64
```

#### 1b. Value types

```cpp
// Constant integer value
struct Const {
    std::uint64_t value;
    Width width;          // bit width of this constant
};

// Named architectural register — modelled as a location in the
// register address space. The lifter assigns offsets; IGNIL itself
// is architecture-agnostic.
//
// Sub-registers share the same base offset:
//   RAX  → Reg{0, 64, "RAX"}
//   EAX  → Reg{0, 32, "EAX"}   (same offset, narrower)
//   AX   → Reg{0, 16, "AX"}
//   AL   → Reg{0,  8, "AL"}
//   AH   → Reg{1,  8, "AH"}   (byte 1 of RAX)
struct Reg {
    std::uint32_t offset; // byte offset in the register address space
    Width width;          // bit width
    std::string name;     // optional human-readable label; used in toString and SliceExpr output
};

// SSA temporary — unique within a Block. No aliasing possible.
struct Temp {
    std::uint32_t id;
    Width width;
};

// Any value usable as operand or destination
using Value = std::variant<Const, Reg, Temp>;

// Returns the bit width of any Value
[[nodiscard]] Width widthOf(const Value &v);
```

#### 1c. Opcode enum

Signedness lives in the opcode only where it matters
(division, remainder, right-shift, comparisons, extension).
For ADD, SUB, AND, OR, XOR, MUL (truncated) the result is
identical for signed and unsigned (two's complement), so
one opcode covers both.

```cpp
enum class Opcode : std::uint8_t {
    // Data movement
    COPY,    // dst = srcs[0]
    LOAD,    // dst = memory[srcs[0]]  (width bytes)
    STORE,   // memory[srcs[0]] = srcs[1]  (no dst)

    // Arithmetic (sign-agnostic)
    ADD, SUB, NEG, MUL,

    // Arithmetic (sign-dependent)
    SDIV, UDIV,
    SMOD, UMOD,

    // Bitwise (sign-agnostic)
    AND, OR, XOR, NOT,
    SHL,    // logical shift left
    SHR,    // logical shift right (zero fill)
    SAR,    // arithmetic shift right (sign fill)

    // Width conversion
    ZEXT,   // zero-extend  srcs[0] to dst width
    SEXT,   // sign-extend  srcs[0] to dst width
    TRUNC,  // truncate     srcs[0] to dst width

    // Comparison — always produce a 1-bit result
    EQ, NEQ,
    ULT, ULE, UGT, UGE,   // unsigned
    SLT, SLE, SGT, SGE,   // signed

    // Control flow
    JMP,    // unconditional — srcs[0] = target address
    CJMP,   // srcs[0] = condition (1-bit)
            // srcs[1] = taken address
            // srcs[2] = not-taken address
    CALL,   // srcs[0] = target address
    RET,    // no operands

    // Symbolic unknown — models unresolvable inputs
    UNDEF,

    // Floating-point (IEEE754 double, width always 64) — same philosophy
    // as signedness above: floatness lives in the opcode, not the value.
    // A Const/Reg/Temp's bits are reinterpreted as a double only when one
    // of these consumes them. Appended after UNDEF rather than grouped
    // with ADD/SUB/MUL where they'd read more naturally: dragon_c.h and
    // python/dragon.py both mirror this enum as hardcoded integer
    // constants, and only a few spot values are compile-time-checked
    // against it (see dragon_c.cpp) — a mid-enum insertion silently shifts
    // every later value with nothing to catch the ones that aren't
    // individually asserted. New opcodes always go at the end.
    FADD, FSUB, FMUL, FDIV,
    SITOFP,  // dst(double) = (double)(signed)srcs[0]
    FPTOSI,  // dst(int) = srcs[0] interpreted as double, truncated toward zero
};
```

#### 1d. Op struct

```cpp
struct Op {
    Opcode opcode;

    // Destination — absent for STORE, JMP, CJMP, CALL, RET
    std::optional<Value> dst;

    // Source operands (count and semantics depend on opcode)
    std::vector<Value> srcs;

    // Address of the machine instruction that produced this Op.
    // Multiple Ops from the same machine instruction share this address.
    // Zero for synthetic Ops.
    std::uint64_t address{};
};
```

#### 1e. Block class

```cpp
class Block {
  public:
  explicit Block(std::uint64_t startAddress);

  void append(Op op);

  [[nodiscard]] const std::vector<Op> &ops()         const;
  [[nodiscard]] std::uint64_t          startAddress() const;
  [[nodiscard]] bool                   empty()        const;
  [[nodiscard]] std::size_t            size()         const;

  auto begin() const;
  auto end()   const;

  private:
  std::uint64_t  startAddress_;
  std::vector<Op> ops_;
};
```

#### 1f. Utility declarations

```cpp
[[nodiscard]] std::string_view opcodeName(Opcode op);
[[nodiscard]] std::string      toString(const Value &v);
[[nodiscard]] std::string      toString(const Op &op);
[[nodiscard]] std::string      toString(const Block &block);
```

---

### Step 2 — Create `lib/lifters/ignil/IGNIL.cpp`

#### 2a. `widthOf`

```cpp
Width dragon::ignil::widthOf(const Value &v) {
    return std::visit([](const auto &val) { return val.width; }, v);
}
```

#### 2b. `Block` methods

```cpp
dragon::ignil::Block::Block(std::uint64_t startAddress)
    : startAddress_(startAddress) {}

void dragon::ignil::Block::append(Op op) {
    ops_.push_back(std::move(op));
}

const std::vector<dragon::ignil::Op> &dragon::ignil::Block::ops() const {
    return ops_;
}

std::uint64_t dragon::ignil::Block::startAddress() const { return startAddress_; }
bool          dragon::ignil::Block::empty()        const { return ops_.empty(); }
std::size_t   dragon::ignil::Block::size()         const { return ops_.size(); }

auto dragon::ignil::Block::begin() const { return ops_.begin(); }
auto dragon::ignil::Block::end()   const { return ops_.end(); }
```

#### 2c. `opcodeName`

```cpp
std::string_view dragon::ignil::opcodeName(Opcode op) {
    switch (op) {
        case Opcode::COPY:  return "COPY";
        case Opcode::LOAD:  return "LOAD";
        case Opcode::STORE: return "STORE";
        case Opcode::ADD:   return "ADD";
        case Opcode::SUB:   return "SUB";
        case Opcode::NEG:   return "NEG";
        case Opcode::MUL:   return "MUL";
        case Opcode::SDIV:  return "SDIV";
        case Opcode::UDIV:  return "UDIV";
        case Opcode::SMOD:  return "SMOD";
        case Opcode::UMOD:  return "UMOD";
        case Opcode::AND:   return "AND";
        case Opcode::OR:    return "OR";
        case Opcode::XOR:   return "XOR";
        case Opcode::NOT:   return "NOT";
        case Opcode::SHL:   return "SHL";
        case Opcode::SHR:   return "SHR";
        case Opcode::SAR:   return "SAR";
        case Opcode::ZEXT:  return "ZEXT";
        case Opcode::SEXT:  return "SEXT";
        case Opcode::TRUNC: return "TRUNC";
        case Opcode::EQ:    return "EQ";
        case Opcode::NEQ:   return "NEQ";
        case Opcode::ULT:   return "ULT";
        case Opcode::ULE:   return "ULE";
        case Opcode::UGT:   return "UGT";
        case Opcode::UGE:   return "UGE";
        case Opcode::SLT:   return "SLT";
        case Opcode::SLE:   return "SLE";
        case Opcode::SGT:   return "SGT";
        case Opcode::SGE:   return "SGE";
        case Opcode::JMP:   return "JMP";
        case Opcode::CJMP:  return "CJMP";
        case Opcode::CALL:  return "CALL";
        case Opcode::RET:   return "RET";
        case Opcode::UNDEF: return "UNDEF";
    }
    return "?";
}
```

#### 2d. `toString`

```cpp
std::string dragon::ignil::toString(const Value &v) {
    return std::visit(overloaded{
        [](const Const &c) {
            return std::format("0x{:x}:i{}", c.value, c.width);
        },
        [](const Reg &r) {
            if (!r.name.empty())
                return std::format("{}:i{}", r.name, r.width);
            return std::format("reg[{}]:i{}", r.offset, r.width);
        },
        [](const Temp &t) {
            return std::format("t{}:i{}", t.id, t.width);
        },
    }, v);
}

std::string dragon::ignil::toString(const Op &op) {
    std::string s;
    if (op.dst)
        s += toString(*op.dst) + " = ";
    s += std::string(opcodeName(op.opcode));
    s += "(";
    for (std::size_t i = 0; i < op.srcs.size(); ++i) {
        if (i) s += ", ";
        s += toString(op.srcs[i]);
    }
    s += ")";
    if (op.address)
        s += std::format("  ; @0x{:x}", op.address);
    return s;
}

std::string dragon::ignil::toString(const Block &block) {
    std::string s = std::format("IGNILBlock @ 0x{:x}\n", block.startAddress());
    for (const auto &op : block)
        s += "  " + toString(op) + "\n";
    return s;
}
```

> **Note:** `overloaded` is a helper needed for multi-lambda `std::visit`.
> Add this to a private utilities header:
> ```cpp
> template<class... Ts>
> struct overloaded : Ts... { using Ts::operator()...; };
> template<class... Ts>
> overloaded(Ts...) -> overloaded<Ts...>;
> ```

---

### Step 3 — Add `ignil::Block` storage to `Graph`

#### 3a. In `Graph.hpp`

```cpp
#include <dragon/IGNIL.hpp>

class Graph {
  public:
  // ... existing API ...

  void           addIGNILBlock(ignil::Block block);
  ignil::Block  *getIGNILBlock(std::uint64_t addr);
  const ignil::Block *getIGNILBlock(std::uint64_t addr) const;

  private:
  // ... existing members ...
  std::map<std::uint64_t, ignil::Block> ignilBlocks_;
};
```

#### 3b. In `Graph.cpp`

```cpp
void dragon::Graph::addIGNILBlock(ignil::Block block) {
    std::uint64_t addr = block.startAddress();
    ignilBlocks_.emplace(addr, std::move(block));
}

dragon::ignil::Block *dragon::Graph::getIGNILBlock(std::uint64_t addr) {
    auto it = ignilBlocks_.find(addr);
    return it != ignilBlocks_.end() ? &it->second : nullptr;
}

const dragon::ignil::Block *dragon::Graph::getIGNILBlock(std::uint64_t addr) const {
    auto it = ignilBlocks_.find(addr);
    return it != ignilBlocks_.end() ? &it->second : nullptr;
}
```

---

### Step 4 — Update `CMakeLists.txt`

Add `IGNIL.cpp` to `lib/CMakeLists.txt`:

```cmake
add_library(libdragon SHARED
    Architecture.cpp
    Instruction.cpp
    BasicBlock.cpp
    Function.cpp
    Graph.cpp
    IGNIL.cpp          # new
)
```

---

## Part 2 — X86 IGNIL Lifter

The lifter translates each machine `Instruction` in a `BasicBlock`
into a sequence of `ignil::Op` objects. It is the only place in the
codebase that knows about x86 register names and semantics.

---

### Step 5 — Define the x86 register address space

The register address space assigns a **byte offset** to every x86/x86_64
register. Sub-registers share the base offset of their parent; width
encodes which bytes they cover.

```
Standard x86_64 register layout
================================
Offset  Register   Width(bits)
------  --------   -----------
0       RAX        64
0       EAX        32  (same base, lower 4 bytes)
0       AX         16
0       AL          8
1       AH          8  (byte 1 of the 16-bit AX view)
8       RCX        64
8       ECX        32
8       CX         16
8       CL          8
9       CH          8
16      RDX        64
16      EDX        32
16      DX         16
16      DL          8
17      DH          8
24      RBX        64
24      EBX        32
24      BX         16
24      BL          8
25      BH          8
32      RSP        64
32      ESP        32
40      RBP        64
40      EBP        32
48      RSI        64
48      ESI        32
56      RDI        64
56      EDI        32
64      R8         64
64      R8D        32
72      R9         64
80      R10        64
88      R11        64
96      R12        64
104     R13        64
112     R14        64
120     R15        64
128     RIP        64

Flags (1-byte slots, 1-bit semantics)
======================================
136     CF          8
137     PF          8
138     AF          8
139     ZF          8
140     SF          8
141     OF          8
142     DF          8
```

This table is owned by the x86 lifter and must not appear in `IGNIL.hpp`
— IGNIL itself is architecture-agnostic.

---

### Step 6 — Create the lifter interface

Create `lib/disassemblers/x86/X86IGNILLifter.hpp`:

```cpp
#pragma once

#include <dragon/IGNIL.hpp>
#include <dragon/Architecture.hpp>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <unordered_map>
#include <cstdint>

namespace dragon {

class BasicBlock;
class Graph;
class Instruction;

namespace x86 {

/// Lifts x86/x86_64 machine instructions to IGNIL.
///
/// Construction scans the MCRegisterInfo once to build the
/// LLVM-register-integer → ignil::Reg mapping. Lifting itself
/// is then a pure integer-comparison dispatch with no string work.
class X86IGNILLifter {
  public:
  X86IGNILLifter(Architecture architecture,
                 const llvm::MCInstrInfo   &instrInfo,
                 const llvm::MCRegisterInfo &regInfo);

  /// Lift a complete basic block into an ignil::Block.
  [[nodiscard]] ignil::Block
  liftBlock(const BasicBlock &block, const Graph &graph) const;

  private:
  // Lift a single instruction, appending Ops to out.
  // tempId is the next available temporary index (incremented as needed).
  void liftInstruction(const Instruction &insn,
                       ignil::Block      &out,
                       std::uint32_t     &tempId) const;

  // Per-opcode lifting helpers
  void liftMov  (const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftAdd  (const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftSub  (const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftXor  (const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftAnd  (const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftOr   (const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftPush (const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftPop  (const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftLea  (const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftCmp  (const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftTest (const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftJcc  (const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftJmp  (const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftCall (const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftRet  (const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;

  // Helpers
  // Translate an LLVM register integer to an ignil::Reg.
  // Returns nullopt for unknown registers (caller emits UNDEF).
  [[nodiscard]] std::optional<ignil::Reg>
  toReg(unsigned llvmReg) const;

  // Allocate a fresh temporary
  [[nodiscard]] ignil::Temp
  newTemp(std::uint32_t &tempId, ignil::Width width) const;

  // Emit UNDEF for a destination register (conservative for
  // instructions we do not yet lift)
  void emitUndef(ignil::Reg dst, std::uint64_t addr, ignil::Block &out) const;

  // EFLAGS helpers — emit standard arithmetic flag updates
  // after an operation whose result is in `result`.
  void emitArithFlags(ignil::Value result, std::uint64_t addr,
                      ignil::Block &out, std::uint32_t &tmp) const;

  Architecture architecture_;

  // Cached opcode integers (same approach as X86Info)
  unsigned opMov64rr_{}, opMov32rr_{};
  unsigned opMov64ri_{}, opMov32ri_{};
  unsigned opMov64rm_{}, opMov32rm_{};
  unsigned opMov64mr_{}, opMov32mr_{};
  unsigned opLea64r_{},  opLea32r_{};
  unsigned opAdd64rr_{}, opAdd32rr_{};
  unsigned opAdd64ri_{}, opAdd32ri_{};
  unsigned opSub64rr_{}, opSub32rr_{};
  unsigned opSub64ri_{}, opSub32ri_{};
  unsigned opXor64rr_{}, opXor32rr_{};
  unsigned opAnd64rr_{}, opAnd32rr_{};
  unsigned opOr64rr_{},  opOr32rr_{};
  unsigned opPush64r_{}, opPop64r_{};
  unsigned opPush32r_{}, opPop32r_{};
  unsigned opCmp64rr_{}, opCmp32rr_{};
  unsigned opCmp64ri_{}, opCmp32ri_{};
  unsigned opTest64rr_{},opTest32rr_{};
  unsigned opJmp64r_{},  opJmp32r_{};  // indirect
  unsigned opJmp_{};                   // direct
  unsigned opCall64r_{};               // indirect
  unsigned opCall_{};                  // direct
  unsigned opRet64_{},   opRetL_{};
  // Conditional jumps (fill per family)
  unsigned opJe_{}, opJne_{};
  unsigned opJl_{}, opJle_{}, opJg_{}, opJge_{};
  unsigned opJb_{}, opJbe_{}, opJa_{}, opJae_{};

  // LLVM register integer → ignil::Reg mapping
  // Built once in constructor by scanning MCRegisterInfo + the
  // static name→offset table below.
  std::unordered_map<unsigned, ignil::Reg> regMap_;

  // Well-known IGNIL Reg objects for flags (looked up by name in ctor)
  ignil::Reg regCF_{}, regPF_{}, regAF_{};
  ignil::Reg regZF_{}, regSF_{}, regOF_{}, regDF_{};
  ignil::Reg regRSP_{}, regESP_{};  // needed for push/pop
};

} // namespace x86
} // namespace dragon
```

---

### Step 7 — Implement `X86IGNILLifter.cpp`

Create `lib/disassemblers/x86/X86IGNILLifter.cpp`.

#### 7a. Static register name → offset table

```cpp
// Full register name → ignil::Reg table for x86/x86_64.
// The table is macro-generated from x86registers.def; each entry carries the
// register name as the third field so toString and SliceExpr output is readable.
static const std::unordered_map<std::string_view, dragon::ignil::Reg>
    kRegisterTable = {
#define REG(name, offset, width) {name, {offset, width, name}},
#include "x86registers.def"
#undef REG
};
```

#### 7b. Constructor

```cpp
dragon::x86::X86IGNILLifter::X86IGNILLifter(
        Architecture architecture,
        const llvm::MCInstrInfo   &instrInfo,
        const llvm::MCRegisterInfo &regInfo)
    : architecture_(architecture) {

    // Build LLVM register integer → ignil::Reg mapping
    for (unsigned i = 0; i < regInfo.getNumRegs(); ++i) {
        std::string_view name = regInfo.getName(i);
        auto it = kRegisterTable.find(name);
        if (it != kRegisterTable.end())
            regMap_.emplace(i, it->second);
    }

    // Cache well-known flag Reg objects for use in flag-update helpers
    auto findReg = [&](std::string_view name) -> ignil::Reg {
        for (unsigned i = 0; i < regInfo.getNumRegs(); ++i)
            if (regInfo.getName(i) == name)
                if (auto it = regMap_.find(i); it != regMap_.end())
                    return it->second;
        return ignil::Reg{0, 0}; // should never happen for well-known regs
    };
    regCF_  = findReg("CF");   regPF_ = findReg("PF");
    regAF_  = findReg("AF");   regZF_ = findReg("ZF");
    regSF_  = findReg("SF");   regOF_ = findReg("OF");
    regDF_  = findReg("DF");
    regRSP_ = findReg("RSP");  regESP_ = findReg("ESP");

    // Scan opcodes by name — same pattern as X86Info
    for (unsigned i = 0; i < instrInfo.getNumOpcodes(); ++i) {
        std::string_view name = instrInfo.getName(i);
        if      (name == "MOV64rr") opMov64rr_ = i;
        else if (name == "MOV32rr") opMov32rr_ = i;
        else if (name == "MOV64ri") opMov64ri_ = i;
        else if (name == "MOV32ri") opMov32ri_ = i;
        else if (name == "LEA64r")  opLea64r_  = i;
        else if (name == "LEA32r")  opLea32r_  = i;
        else if (name == "ADD64rr") opAdd64rr_ = i;
        else if (name == "ADD32rr") opAdd32rr_ = i;
        else if (name == "ADD64ri32") opAdd64ri_ = i;
        else if (name == "ADD32ri") opAdd32ri_ = i;
        else if (name == "SUB64rr") opSub64rr_ = i;
        else if (name == "SUB32rr") opSub32rr_ = i;
        else if (name == "XOR64rr") opXor64rr_ = i;
        else if (name == "XOR32rr") opXor32rr_ = i;
        else if (name == "AND64rr") opAnd64rr_ = i;
        else if (name == "AND32rr") opAnd32rr_ = i;
        else if (name == "OR64rr")  opOr64rr_  = i;
        else if (name == "OR32rr")  opOr32rr_  = i;
        else if (name == "PUSH64r") opPush64r_ = i;
        else if (name == "POP64r")  opPop64r_  = i;
        else if (name == "CMP64rr") opCmp64rr_ = i;
        else if (name == "CMP32rr") opCmp32rr_ = i;
        else if (name == "TEST64rr")opTest64rr_= i;
        else if (name == "TEST32rr")opTest32rr_= i;
        else if (name == "JMP64r")  opJmp64r_  = i;
        else if (name == "JMP_1" || name == "JMP")  opJmp_ = i;
        else if (name == "CALL64r") opCall64r_ = i;
        else if (name == "CALL64pcrel32") opCall_ = i;
        else if (name == "RET64")   opRet64_   = i;
        else if (name == "RETL")    opRetL_    = i;
        else if (name == "JE_1"  || name == "JE")   opJe_  = i;
        else if (name == "JNE_1" || name == "JNE")  opJne_ = i;
        else if (name == "JL_1"  || name == "JL")   opJl_  = i;
        else if (name == "JLE_1" || name == "JLE")  opJle_ = i;
        else if (name == "JG_1"  || name == "JG")   opJg_  = i;
        else if (name == "JGE_1" || name == "JGE")  opJge_ = i;
        else if (name == "JB_1"  || name == "JB")   opJb_  = i;
        else if (name == "JBE_1" || name == "JBE")  opJbe_ = i;
        else if (name == "JA_1"  || name == "JA")   opJa_  = i;
        else if (name == "JAE_1" || name == "JAE")  opJae_ = i;
    }
}
```

> **Note:** LLVM uses suffixes like `_1`, `_2`, `_4` for short/near/far
> variants of jumps. You may need to check the exact names with a debug
> print over `instrInfo.getNumOpcodes()` if the above names don't match.

#### 7c. `toReg` and `newTemp`

```cpp
std::optional<dragon::ignil::Reg>
dragon::x86::X86IGNILLifter::toReg(unsigned llvmReg) const {
    auto it = regMap_.find(llvmReg);
    if (it == regMap_.end()) return std::nullopt;
    return it->second;
}

dragon::ignil::Temp
dragon::x86::X86IGNILLifter::newTemp(std::uint32_t &tempId,
                                      ignil::Width   width) const {
    return ignil::Temp{tempId++, width};
}

void dragon::x86::X86IGNILLifter::emitUndef(ignil::Reg    dst,
                                              std::uint64_t addr,
                                              ignil::Block &out) const {
    ignil::Op op;
    op.opcode  = ignil::Opcode::UNDEF;
    op.dst     = dst;
    op.address = addr;
    out.append(std::move(op));
}
```

#### 7d. Flag update helper

Most arithmetic instructions update CF, PF, AF, ZF, SF, OF.
AF (auxiliary carry) is complex; model it as UNDEF conservatively.
CF and OF depend on the operation (add vs sub); emit UNDEF for now
and refine later.

```cpp
void dragon::x86::X86IGNILLifter::emitArithFlags(
        ignil::Value result, std::uint64_t addr,
        ignil::Block &out, std::uint32_t &tmp) const {

    // ZF = (result == 0)
    auto zfTemp = newTemp(tmp, 1);
    out.append({ignil::Opcode::EQ,  zfTemp,
                {result, ignil::Const{0, ignil::widthOf(result)}}, addr});
    out.append({ignil::Opcode::COPY, regZF_, {zfTemp}, addr});

    // SF = (result < 0)  — signed less-than zero
    auto sfTemp = newTemp(tmp, 1);
    out.append({ignil::Opcode::SLT, sfTemp,
                {result, ignil::Const{0, ignil::widthOf(result)}}, addr});
    out.append({ignil::Opcode::COPY, regSF_, {sfTemp}, addr});

    // CF, OF, AF — model as UNDEF (conservative; refine per-instruction later)
    emitUndef(regCF_, addr, out);
    emitUndef(regOF_, addr, out);
    emitUndef(regAF_, addr, out);

    // PF — parity of lowest byte; model as UNDEF for now
    emitUndef(regPF_, addr, out);
}
```

#### 7e. Example instruction lifters

**MOV reg, reg**

```cpp
void dragon::x86::X86IGNILLifter::liftMov(
        const llvm::MCInst &mc, std::uint64_t addr,
        ignil::Block &out, std::uint32_t &tmp) const {

    auto dst = toReg(mc.getOperand(0).getReg());
    auto src = toReg(mc.getOperand(1).getReg());
    if (!dst || !src) { emitUndef(*dst, addr, out); return; }

    out.append({ignil::Opcode::COPY, *dst, {*src}, addr});
}
```

**ADD reg, reg**

```cpp
void dragon::x86::X86IGNILLifter::liftAdd(
        const llvm::MCInst &mc, std::uint64_t addr,
        ignil::Block &out, std::uint32_t &tmp) const {

    auto dst = toReg(mc.getOperand(0).getReg());
    auto src = toReg(mc.getOperand(1).getReg());
    if (!dst || !src) { emitUndef(*dst, addr, out); return; }

    auto result = newTemp(tmp, dst->width);
    out.append({ignil::Opcode::ADD, result, {*dst, *src}, addr});
    out.append({ignil::Opcode::COPY, *dst, {result}, addr});
    emitArithFlags(result, addr, out, tmp);
}
```

**PUSH reg**

```cpp
void dragon::x86::X86IGNILLifter::liftPush(
        const llvm::MCInst &mc, std::uint64_t addr,
        ignil::Block &out, std::uint32_t &tmp) const {

    auto src = toReg(mc.getOperand(0).getReg());
    if (!src) return;

    ignil::Width ptrWidth = (architecture_ == Architecture::X86_64) ? 64 : 32;
    ignil::Reg   sp = (architecture_ == Architecture::X86_64) ? regRSP_ : regESP_;
    ignil::Width srcBytes = src->width / 8;

    // RSP -= size
    auto newSP = newTemp(tmp, ptrWidth);
    out.append({ignil::Opcode::SUB, newSP,
                {sp, ignil::Const{srcBytes, ptrWidth}}, addr});
    out.append({ignil::Opcode::COPY, sp, {newSP}, addr});

    // memory[RSP] = src
    out.append({ignil::Opcode::STORE, std::nullopt, {sp, *src}, addr});
}
```

**POP reg**

```cpp
void dragon::x86::X86IGNILLifter::liftPop(
        const llvm::MCInst &mc, std::uint64_t addr,
        ignil::Block &out, std::uint32_t &tmp) const {

    auto dst = toReg(mc.getOperand(0).getReg());
    if (!dst) return;

    ignil::Width ptrWidth = (architecture_ == Architecture::X86_64) ? 64 : 32;
    ignil::Reg   sp = (architecture_ == Architecture::X86_64) ? regRSP_ : regESP_;
    ignil::Width dstBytes = dst->width / 8;

    // dst = memory[RSP]
    auto loaded = newTemp(tmp, dst->width);
    out.append({ignil::Opcode::LOAD, loaded, {sp}, addr});
    out.append({ignil::Opcode::COPY, *dst, {loaded}, addr});

    // RSP += size
    auto newSP = newTemp(tmp, ptrWidth);
    out.append({ignil::Opcode::ADD, newSP,
                {sp, ignil::Const{dstBytes, ptrWidth}}, addr});
    out.append({ignil::Opcode::COPY, sp, {newSP}, addr});
}
```

**CMP reg, reg** (sets flags, no result register)

```cpp
void dragon::x86::X86IGNILLifter::liftCmp(
        const llvm::MCInst &mc, std::uint64_t addr,
        ignil::Block &out, std::uint32_t &tmp) const {

    auto lhs = toReg(mc.getOperand(0).getReg());
    auto rhs = toReg(mc.getOperand(1).getReg());
    if (!lhs || !rhs) return;

    // CMP is SUB that discards the result but keeps the flags
    auto result = newTemp(tmp, lhs->width);
    out.append({ignil::Opcode::SUB, result, {*lhs, *rhs}, addr});
    emitArithFlags(result, addr, out, tmp);
}
```

**JLE (je, jne, etc.) — conditional jumps**

Condition encoding:

| Instruction | Condition in IGNIL |
|---|---|
| JE / JZ | ZF |
| JNE / JNZ | NOT ZF |
| JL / JNGE | SF XOR OF |
| JLE / JNG | (SF XOR OF) OR ZF |
| JG / JNLE | NOT ((SF XOR OF) OR ZF) |
| JGE / JNL | NOT (SF XOR OF) |
| JB / JC | CF |
| JBE / JNA | CF OR ZF |
| JA / JNBE | NOT (CF OR ZF) |
| JAE / JNB | NOT CF |

```cpp
void dragon::x86::X86IGNILLifter::liftJcc(
        const llvm::MCInst &mc, std::uint64_t addr,
        ignil::Block &out, std::uint32_t &tmp) const {

    // Target is the immediate operand (already resolved to absolute
    // address by the disassembler via insn.branches())
    ignil::Const target{mc.getOperand(0).getImm(), 64};
    ignil::Const fallthrough{addr + 2, 64}; // approximate — use actual insn size

    unsigned opc = mc.getOpcode();
    ignil::Value cond{ignil::Temp{0, 1}}; // placeholder

    if (opc == opJe_) {
        cond = ignil::Value{regZF_};

    } else if (opc == opJne_) {
        auto t = newTemp(tmp, 1);
        out.append({ignil::Opcode::XOR, t,
                    {regZF_, ignil::Const{1, 1}}, addr}); // NOT ZF
        cond = t;

    } else if (opc == opJl_) {
        auto t = newTemp(tmp, 1);
        out.append({ignil::Opcode::XOR, t, {regSF_, regOF_}, addr});
        cond = t;

    } else if (opc == opJle_) {
        auto xorT = newTemp(tmp, 1);
        out.append({ignil::Opcode::XOR, xorT, {regSF_, regOF_}, addr});
        auto orT = newTemp(tmp, 1);
        out.append({ignil::Opcode::OR, orT, {xorT, regZF_}, addr});
        cond = orT;

    } else if (opc == opJb_) {
        cond = ignil::Value{regCF_};
    }
    // ... add remaining families ...

    out.append({ignil::Opcode::CJMP, std::nullopt,
                {cond, target, fallthrough}, addr});
}
```

**Indirect JMP**

```cpp
void dragon::x86::X86IGNILLifter::liftJmp(
        const llvm::MCInst &mc, std::uint64_t addr,
        ignil::Block &out, std::uint32_t &tmp) const {

    if (mc.getOpcode() == opJmp_) {
        // Direct — target is immediate
        ignil::Const target{static_cast<std::uint64_t>(mc.getOperand(0).getImm()), 64};
        out.append({ignil::Opcode::JMP, std::nullopt, {target}, addr});
    } else {
        // Indirect — target is a register; backward slicing from here
        // resolves jump tables
        auto target = toReg(mc.getOperand(0).getReg());
        if (!target) {
            auto undef = newTemp(tmp, 64);
            out.append({ignil::Opcode::UNDEF, undef, {}, addr});
            out.append({ignil::Opcode::JMP, std::nullopt, {undef}, addr});
        } else {
            out.append({ignil::Opcode::JMP, std::nullopt, {*target}, addr});
        }
    }
}
```

#### 7f. Main dispatch

```cpp
void dragon::x86::X86IGNILLifter::liftInstruction(
        const Instruction &insn, ignil::Block &out,
        std::uint32_t &tempId) const {

    const auto *mc = insn.mcInst();
    if (!mc) return;

    unsigned opc = mc->getOpcode();
    std::uint64_t addr = insn.address();

    if      (opc == opMov64rr_ || opc == opMov32rr_) liftMov (*mc, addr, out, tempId);
    else if (opc == opAdd64rr_ || opc == opAdd32rr_) liftAdd (*mc, addr, out, tempId);
    else if (opc == opSub64rr_ || opc == opSub32rr_) liftSub (*mc, addr, out, tempId);
    else if (opc == opXor64rr_ || opc == opXor32rr_) liftXor (*mc, addr, out, tempId);
    else if (opc == opAnd64rr_ || opc == opAnd32rr_) liftAnd (*mc, addr, out, tempId);
    else if (opc == opOr64rr_  || opc == opOr32rr_)  liftOr  (*mc, addr, out, tempId);
    else if (opc == opPush64r_ || opc == opPush32r_) liftPush(*mc, addr, out, tempId);
    else if (opc == opPop64r_  || opc == opPop32r_)  liftPop (*mc, addr, out, tempId);
    else if (opc == opCmp64rr_ || opc == opCmp32rr_) liftCmp (*mc, addr, out, tempId);
    else if (opc == opJmp64r_  || opc == opJmp_)     liftJmp (*mc, addr, out, tempId);
    else if (opc == opRet64_   || opc == opRetL_)    liftRet (*mc, addr, out, tempId);
    else if (opc == opJe_ || opc == opJne_ || opc == opJl_ ||
             opc == opJle_|| opc == opJg_  || opc == opJge_||
             opc == opJb_ || opc == opJbe_ || opc == opJa_ ||
             opc == opJae_)                           liftJcc (*mc, addr, out, tempId);
    // Unknown — leave unlisted instructions as gaps (no UNDEF emitted for
    // instructions with no IGNIL-visible side effects, e.g. prefetch, fence)
}
```

#### 7g. `liftBlock`

```cpp
dragon::ignil::Block dragon::x86::X86IGNILLifter::liftBlock(
        const BasicBlock &block, const Graph &graph) const {

    ignil::Block result{block.startAddress()};
    std::uint32_t tempId = 0;

    for (const Instruction *insn : block.instructions())
        liftInstruction(*insn, result, tempId);

    return result;
}
```

---

### Step 8 — Integrate into `X86Analysis`

In `X86Analysis`, after `discoverFunctionStarts` and before populating
the graph, add a lifting pass:

```cpp
// In X86Analysis::analyze(), after the discovery passes:

static const X86IGNILLifter lifter32{Architecture::X86_32, instrInfo_, regInfo_};
static const X86IGNILLifter lifter64{Architecture::X86_64, instrInfo_, regInfo_};
const X86IGNILLifter &lifter =
    (architecture_ == Architecture::X86_32) ? lifter32 : lifter64;

// Populate graph first so BasicBlock views work
for (auto &insn : instructions)
    graph.addInstruction(std::move(insn));
for (std::uint64_t addr : basicBlockStarts)
    graph.addBlock(addr);
for (std::uint64_t addr : functionStarts)
    graph.addFunction(addr);

// Now lift each block and store the IGNIL in the graph
for (const BasicBlock &bb : graph.blocks()) {
    ignil::Block ib = lifter.liftBlock(bb, graph);
    graph.addIGNILBlock(std::move(ib));
}
```

---

### Step 9 — Backward slicing

`BackwardSlicer` (in `include/dragon/analysis/BackwardSlicer.hpp`) walks IGNIL
ops backward from a given value and block, crossing block boundaries only
when there is a unique predecessor (no join nodes). The result is a
`SliceExpr` tree (`include/dragon/analysis/SliceExpr.hpp`).

```cpp
#include <dragon/analysis/BackwardSlicer.hpp>
#include <dragon/analysis/SliceExpr.hpp>
#include <dragon/lifters/ignil/x86/x86IGNILRegs.hpp>

// graph must be populated by Disassembler::disassemble(bytes, base_addr, graph)
// — block_addr must be the start address of an IGNIL block, not an arbitrary
// instruction address inside it
dragon::BackwardSlicer slicer(/*maxBlocks=*/5);
auto expr = slicer.slice(dragon::x86::ZF, block_addr, graph);
std::cout << dragon::slice::toString(expr) << "\n";
// EQ(SUB(RAX:i64, RBX:i64), 0x0:i64)
```

The same call works unchanged on AArch64 — use
`include/dragon/lifters/ignil/arm/armIGNILRegs.hpp` and `dragon::arm` instead:

```cpp
auto expr = slicer.slice(dragon::arm::ZF, block_addr, graph);
// e.g. cmp w0, #5  ->  EQ(SUB(W0:i32, 0x5:i32), 0x0:i32)
```

**SliceExpr node types**

| Variant | Fields | Meaning |
|---|---|---|
| `Const` | `value`, `width` | Folded constant |
| `SymReg` | `reg` (offset, width, name) | Unresolved architectural register |
| `BinOp` | `op`, `left`, `right` | Binary operation |
| `UnaryOp` | `op`, `operand` | Unary operation |
| `Load` | `addr`, `width` | Memory read |
| `Undef` | — | Unresolvable / not lifted |

Walking the tree uses `std::visit` on `expr.value`:

```cpp
using namespace dragon::slice;
std::visit(utils::overloaded{
    [](const Const   &c) { std::cout << "constant " << c.value << "\n"; },
    [](const SymReg  &r) { std::cout << "register " << r.reg.name << "\n"; },
    [](const BinOp   &b) { /* recurse into *b.left and *b.right */ },
    [](const UnaryOp &u) { /* recurse into *u.operand */ },
    [](const Load    &l) { /* recurse into *l.addr */ },
    [](const Undef   &)  { std::cout << "undef\n"; },
}, expr.value);
```

For jump-table resolution, the intended workflow remains:

```
1. Find JMP(Temp{N}) in the lifted block
2. Slice Temp{N} → typically LOAD(ADD(MUL(SymReg{index}, 8), base_addr))
3. Locate the bound check feeding the guarding CJMP
4. Enumerate entries and enqueue targets into blocks_q
```

---

## Part 3 — Testing

### Step 10 — IGNIL type tests

Create `tests/ignil/TestIGNIL.cpp`:

```cpp
TEST_CASE("IGNIL — widthOf") {
    REQUIRE(ignil::widthOf(ignil::Const{42, 32}) == 32);
    REQUIRE(ignil::widthOf(ignil::Reg{0, 64})    == 64);
    REQUIRE(ignil::widthOf(ignil::Temp{0, 1})    ==  1);
}

TEST_CASE("IGNIL — Block append and iterate") {
    ignil::Block b{0x1000};
    b.append({ignil::Opcode::COPY,
              ignil::Reg{0, 64},
              {ignil::Reg{8, 64}},
              0x1000});
    REQUIRE(b.size() == 1);
    REQUIRE(b.ops()[0].opcode == ignil::Opcode::COPY);
}

TEST_CASE("IGNIL — multiple ops share address") {
    ignil::Block b{0x1000};
    b.append({ignil::Opcode::ADD,  ignil::Temp{0,64}, {}, 0x1004});
    b.append({ignil::Opcode::COPY, ignil::Reg{0,64},  {}, 0x1004});
    b.append({ignil::Opcode::COPY, ignil::Reg{139,8}, {}, 0x1004});
    // All three share address 0x1004 (one ADD instruction → three ops)
    for (const auto &op : b)
        REQUIRE(op.address == 0x1004);
}
```

### Step 11 — Lifter tests

```cpp
TEST_CASE("X86IGNILLifter — mov rbp, rsp produces one COPY") {
    // push rbp / mov rbp, rsp / ret
    // Lift the second block and verify the COPY
}

TEST_CASE("X86IGNILLifter — push rbp produces SUB + STORE") {
    // push rbp
    // Expect: SUB(RSP, 8), STORE(RSP, RBP)
}

TEST_CASE("X86IGNILLifter — indirect jump preserved as JMP(Reg)") {
    // jmp rax (FF E0)
    // Expect: JMP(reg[0]:i64)  (RAX is at offset 0)
}
```

---

## Part 4 — References

### Books

- **Practical Binary Analysis** — Dennis Andriesse (2019, No Starch Press)
  The most practical book on the subject. Covers disassembly algorithms,
  instrumentation, and binary analysis techniques. Highly recommended as
  a companion to this project.

- **Engineering a Compiler** — Cooper & Torczon (2011, Morgan Kaufmann)
  Excellent coverage of IR design, SSA construction, and data flow
  analysis. Relevant for understanding the theory behind IGNIL.

- **Modern Compiler Implementation in C** — Andrew Appel (1998, Cambridge)
  Concise treatment of IR design and analysis passes. Available in
  ML, Java, and C editions.

- **Practical Malware Analysis** — Sikorski & Honig (2012, No Starch Press)
  Strong focus on binary analysis at the instruction level. Good context
  for understanding what analyses matter in practice.

### Papers

- **SoK: All You Ever Wanted to Know About x86/x64 Binary Disassembly
  But Were Afraid to Ask** — Pang et al. (IEEE S&P 2021)
  Already in your reading list. The most comprehensive survey on
  disassembly. Pay attention to Sections 4 (CFG recovery) and 6
  (evaluation of tools including angr and Ghidra).

- **angr: A System for Binary Analysis** — Shoshitaishvili et al.
  (IEEE S&P 2016)
  Describes angr's architecture including VEX IR lifting, the CFG
  recovery engine, and symbolic execution. Directly relevant to
  what IGNIL and the X86IGNILLifter are doing.

- **BAP: A Binary Analysis Platform** — Brumley et al. (CAV 2011)
  Introduces BIL (Binary Intermediate Language), a clean IL with
  explicit flag semantics. Very close in spirit to IGNIL. Read this
  before finalising the IGNIL opcode set.

- **Valgrind: A Framework for Heavyweight Dynamic Binary
  Instrumentation** — Nethercote & Seward (PLDI 2007)
  Describes VEX IR and the lifting pipeline in detail. The IRSB
  (IR Super Block) concept is what informed IGNIL's block ownership.

- **A Semantics for x86-64 Instructions** — Dasgupta et al. (OOPSLA 2019)
  Formal x86-64 semantics in K framework. Extremely useful as a
  reference when implementing flag semantics in the lifter. Covers
  every flag update rule precisely.

- **Unleashing MAYHEM on Binary Code** — Cha et al. (IEEE S&P 2012)
  Describes a system that combines CFG recovery and symbolic
  execution. Good motivation for why indirect jump resolution matters.

- **Program Analysis via Graph Reachability** — Reps (1997)
  Theoretical foundation for data flow analysis and backward slicing.
  Relevant for implementing the backward slice over IGNIL blocks.

- **Static Single Assignment Book** — Braun et al.
  Free online: `ssabook.gforge.inria.fr`
  Everything about SSA form. Read if you decide to convert IGNIL
  blocks to SSA for analysis.

- **Ghidra P-CODE Reference Manual**
  Available in the Ghidra installation under `docs/languages/`.
  The most detailed specification of a practical binary analysis IL.
  Read alongside the BAP paper for a complete picture of IL design.

---

---

## Part 5 — IGNIL to LLVM IR

This section sketches the design for lifting IGNIL blocks to LLVM IR.
The design goal is to reuse the IGNIL blocks already stored in the `Graph`
and produce an `llvm::Module` containing one LLVM function per lifted
function.

---

### Why allocas — no PHI placement required

A naive LLVM lifter has to solve SSA construction: at every control-flow
join point it must insert a PHI node for every register that was written
in more than one predecessor. Computing this correctly requires the
iterated dominance frontier algorithm (Lengauer-Tarjan), which is
non-trivial to implement.

The alloca trick sidesteps this entirely. Instead of emitting PHI nodes,
every architectural register gets one `alloca` in the LLVM function's
entry block. Reads become `load` and writes become `store`. When two
paths write to the same register and then join:

```
block_a:                    block_b:
  store i64 %val_a, ptr %rax  store i64 %val_b, ptr %rax
  br label %join              br label %join

join:
  %v = load i64, ptr %rax   ; no PHI needed — alloca is the merge point
```

LLVM's `mem2reg` pass then:
1. Computes the dominance frontier for each alloca's definition points.
2. Inserts PHI nodes exactly where they are needed.
3. Replaces all `load`/`store` pairs with SSA values.
4. Removes the allocas.

The resulting IR is identical to what a hand-written SSA lifter would
produce, but the lifter itself never has to implement dominance
computation.

---

### Register file: one alloca per `(offset, width)` pair

Because every `Reg` in IGNIL carries both `offset` and `width`, the
lifter can:

- Identify which architectural register is accessed (`offset` uniquely
  identifies the root register — e.g. offset 0 = RAX family).
- Know the exact sub-register being read or written (`width` selects the
  slice — 64 = RAX, 32 = EAX, 16 = AX, 8 = AL/AH).

The lifter scans all IGNIL ops in all blocks of the function before
emitting any IR, collecting every unique `(offset, width)` pair seen in
any `Reg` operand. One alloca is created per pair in the function's entry
block. No information beyond the IGNIL blocks is needed — the x86
IGNILLifter already resolved register names to `(offset, width)` tuples
when it lifted the machine instructions.

```cpp
// RegFile[offset][width] → alloca for that (offset, width) slot
using RegFile = std::map<uint32_t, std::map<ignil::Width, llvm::AllocaInst *>>;
```

---

### Sub-register aliasing: `mergeIntoParent`

Writing to a narrow sub-register must propagate into all wider allocas
that share the same base offset. For example, writing EAX (`Reg{0, 32}`)
must also update RAX (`Reg{0, 64}`).

After storing the new value to the `(offset, smallWidth)` alloca, for
every `bigWidth > smallWidth` that also exists in the reg file at the
same offset:

```
1. Load the current parent value:
   %parent = load i{bigWidth}, ptr regs[offset][bigWidth]

2. Zero out the sub-register's bits with a bit mask:
   mask     = (1 << smallWidth) - 1        ; e.g. 0x00000000FFFFFFFF for EAX
   %cleared = and i{bigWidth} %parent, ~mask

3. Zero-extend the new value and OR it in:
   %ext    = zext i{smallWidth} %new_val to i{bigWidth}
   %merged = or i{bigWidth} %cleared, %ext

4. Store back:
   store i{bigWidth} %merged, ptr regs[offset][bigWidth]
```

`instcombine` folds the mask-and-OR patterns away after `mem2reg`
promotes the allocas to SSA, so the overhead exists only in the unoptimised
IR.

---

### IGNIL → LLVM IR opcode mapping

| IGNIL opcode | LLVM IR |
|---|---|
| `COPY dst, src` | `store` resolved `src` into `dst` alloca |
| `LOAD dst, addr` | `load iN, ptr (gep mem, addr)` |
| `STORE addr, val` | `store iN val, ptr (gep mem, addr)` |
| `ADD` | `add` |
| `SUB` | `sub` |
| `NEG` | `sub iN 0, src` |
| `MUL` | `mul` |
| `SDIV / UDIV` | `sdiv / udiv` |
| `SMOD / UMOD` | `srem / urem` |
| `AND / OR / XOR` | `and / or / xor` |
| `NOT` | `xor src, -1` |
| `SHL / SHR / SAR` | `shl / lshr / ashr` |
| `ZEXT / SEXT / TRUNC` | `zext / sext / trunc` |
| `EQ / NEQ` | `icmp eq / icmp ne` |
| `ULT/ULE/UGT/UGE` | `icmp ult / ule / ugt / uge` |
| `SLT/SLE/SGT/SGE` | `icmp slt / sle / sgt / sge` |
| `JMP target` | `br label %bb_<target>` (when target is a known block) |
| `CJMP cond, taken, fall` | `br i1 %cond, label %bb_<taken>, label %bb_<fall>` |
| `CALL target` | `call void @fn_<target>()` |
| `RET` | `ret void` |
| `UNDEF` | `undef` constant of the appropriate integer type |

---

### `LLVMLifter` class sketch

```cpp
// include/dragon/LLVMLifter.hpp
#pragma once
#include <dragon/IGNIL.hpp>
#include <dragon/Graph.hpp>
#include <dragon/Function.hpp>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/IRBuilder.h>
#include <map>
#include <memory>
#include <string_view>

namespace dragon {

class LLVMLifter {
public:
    explicit LLVMLifter(Architecture arch,
                        std::string_view moduleName = "lifted");
    ~LLVMLifter();

    // Lift one function (all its IGNIL blocks must be in the graph).
    bool lift(const Function &fn, const Graph &graph);

    // Run optimization passes in the recommended order.
    void runMem2Reg();        // promotes allocas → SSA, inserts PHIs
    void runInstCombine();    // folds sub-register mask/OR patterns
    void runGVN();            // eliminates redundant loads
    void runDCE();            // removes dead flag computations

    [[nodiscard]] std::string ir() const;   // dump textual LLVM IR
    [[nodiscard]] llvm::Module &module();

private:
    // All allocas for one lifted function.
    // Outer key: register byte offset.
    // Inner key: bit width.
    using RegFile = std::map<std::uint32_t,
                             std::map<ignil::Width, llvm::AllocaInst *>>;

    // SSA values produced by Temp operands within the current block.
    using TempMap = std::map<std::uint32_t, llvm::Value *>;

    // First pass: scan every IGNIL op in every block of the function,
    // collect all (offset, width) pairs, emit one alloca per pair in
    // the entry block.
    RegFile buildRegFile(llvm::Function *llfn,
                         const Function &fn,
                         const Graph &graph);

    // Map each IGNIL block address to an llvm::BasicBlock.
    std::map<std::uint64_t, llvm::BasicBlock *>
    buildBlockMap(llvm::Function *llfn,
                  const Function &fn,
                  const Graph &graph);

    // Lower one IGNIL block into its llvm::BasicBlock.
    void liftBlock(const ignil::Block &ib,
                   llvm::Function *llfn,
                   RegFile &regs,
                   TempMap &temps,
                   llvm::Value *memPtr,
                   const std::map<std::uint64_t, llvm::BasicBlock *> &bbMap);

    // Lower one IGNIL Op; records the result in `temps` if the op has a
    // Temp destination.
    void liftOp(const ignil::Op &op,
                RegFile &regs,
                TempMap &temps,
                llvm::Value *memPtr,
                llvm::IRBuilder<> &builder,
                const std::map<std::uint64_t, llvm::BasicBlock *> &bbMap);

    // Resolve an ignil::Value to an llvm::Value (load from alloca or
    // look up the temp SSA value).
    llvm::Value *resolve(const ignil::Value &v,
                         RegFile &regs,
                         const TempMap &temps,
                         llvm::IRBuilder<> &builder);

    // After writing `value` (of `width` bits) to `offset`, propagate
    // into every wider alloca that exists at the same offset.
    void mergeIntoParent(std::uint32_t offset,
                         ignil::Width width,
                         llvm::Value *value,
                         RegFile &regs,
                         llvm::IRBuilder<> &builder);

    Architecture arch_;
    std::unique_ptr<llvm::LLVMContext> ctx_;
    std::unique_ptr<llvm::Module> module_;
};

} // namespace dragon
```

---

### Lifted function layout

The lifted LLVM function for a binary function at address `0x401000` looks
like this before any optimisation passes:

```llvm
define void @fn_401000(ptr %mem) {
entry:
  ; one alloca per (offset, width) pair found across all IGNIL blocks
  %rax  = alloca i64         ; Reg{0, 64}
  %eax  = alloca i32         ; Reg{0, 32}   — same offset, narrower
  %rbx  = alloca i64         ; Reg{24, 64}
  %rsp  = alloca i64         ; Reg{32, 64}
  %zf   = alloca i8          ; Reg{139, 8}  — zero flag
  %sf   = alloca i8          ; Reg{140, 8}  — sign flag
  ; ... all registers seen in any op of any block ...
  br label %bb_401000

bb_401000:
  ; IGNIL: COPY RAX = RSP     →    load + store (mergeIntoParent updates %eax too)
  %v0 = load  i64, ptr %rsp
  store i64 %v0, ptr %rax
  ; zero out low 32 bits of rax alloca and OR in truncated value:
  %v0_trunc  = trunc i64 %v0 to i32
  store i32 %v0_trunc, ptr %eax
  ; ... further ops ...
  br i1 %cond, label %bb_401020, label %bb_401030

bb_401020:
  ; ...
  ret void
}
```

After `mem2reg`:

```llvm
define void @fn_401000(ptr %mem) {
entry:
  br label %bb_401000

bb_401000:
  %v0 = load i64, ptr %rsp_addr   ; only real memory accesses remain
  ; ... SSA values, no alloca loads/stores ...
  br i1 %cond_ssa, label %bb_401020, label %bb_401030

bb_401020:
  ; PHI nodes inserted by mem2reg at join points, e.g.:
  %rax.phi = phi i64 [ %val_a, %bb_401000 ], [ %val_b, %bb_401010 ]
  ret void
}
```

---

### Optimisation pipeline

Run passes in this order for best results:

```
mem2reg       — promote allocas to SSA, insert PHIs
instcombine   — fold sub-register mask/OR patterns, constant folding
GVN           — eliminate redundant flag computations and redundant loads
DCE           — remove dead flag slots (CF/OF/AF/PF when not used downstream)
```

Each pass is available through `llvm::PassBuilder` (new pass manager) or
directly via `llvm::createPromoteMemoryToRegisterPass()` etc.

---

## Quick reference — IGNIL lifting examples

```
Machine instruction         IGNIL ops
===================         =========

mov rbp, rsp                COPY RBP:i64 = (RSP:i64)

add rax, rbx                t0:i64 = ADD(RAX:i64, RBX:i64)
                            COPY RAX:i64 = (t0:i64)
                            t1:i1  = EQ(t0:i64, 0x0:i64)
                            COPY ZF:i8 = (t1:i1)
                            t2:i1  = SLT(t0:i64, 0x0:i64)
                            COPY SF:i8 = (t2:i1)
                            UNDEF CF:i8
                            UNDEF OF:i8
                            UNDEF AF:i8
                            UNDEF PF:i8

push rbp                    t0:i64 = SUB(RSP:i64, 0x8:i64)
                            COPY RSP:i64 = (t0:i64)
                            STORE(RSP:i64, RBP:i64)

jle 0x1010                  t0:i1 = XOR(SF:i8, OF:i8)
                            t1:i1 = OR(t0:i1, ZF:i8)
                            CJMP(t1:i1, 0x1010:i64, 0x1008:i64)

jmp rax                     JMP(RAX:i64)   ; backward slice from here
                                            ; to resolve jump table
```

---

## Part 6 — Backward Slicing: Z3 Integration and Switch Analysis

This section describes the planned enhancements to the backward slicing
pipeline:

1. Fix `successorsOf` to handle indirect jumps.
2. Add a Z3 lowerer that converts `SliceExpr` trees to Z3 bitvector
   formulas.
3. Add value enumeration — given a `SliceExpr`, collect all concrete
   values it can take under a set of constraints.
4. Add switch detection — identify the `JMP(Temp ← LOAD(addr_expr))`
   pattern, harvest the bound constraint from the guarding `CJMP`, and
   enumerate all jump-table entries via Z3.

---

### 6.1 — Fix `successorsOf` for indirect jumps

**The bug.** `successorsOf` (in `BackwardSlicer.cpp`) builds the
predecessor map by inspecting each block's terminal op. It currently only
extracts a successor when the target is a `Const`:

```cpp
auto pushConst = [&](const ignil::Value &v) {
    if (const auto *c = std::get_if<ignil::Const>(&v))
        succs.push_back(c->value);
};
```

For an indirect jump (`JMP(Temp{N})`) or an indirect call the target is
a `Temp`, not a `Const`. The function returns an empty list, so those
blocks are never counted as predecessors. Any block whose only real
predecessors jump indirectly will appear to have zero predecessors —
making it look like an entry block in the pred-map — and backward slicing
will stop prematurely or cross incorrectly.

**The fix.** Extend `successorsOf` to also call an optional "indirect
target" callback when the target is not a constant, so callers can
decide what to do with it. For the predecessor map, we simply skip
non-constant targets (we cannot statically know where they land), but we
must not omit them from the successor count of the source block:

```cpp
// Collect all statically-known successors AND flag whether the block
// ends with an indirect (unresolved) transfer.
struct SuccessorInfo {
    std::vector<std::uint64_t> known;   // statically-resolved targets
    bool hasIndirect = false;           // true when JMP/CALL target is a Temp
};

static SuccessorInfo successorsOf(const ignil::Block &block) {
    if (block.empty()) return {};
    const ignil::Op &last = block.ops().back();
    SuccessorInfo info;

    auto pushValue = [&](const ignil::Value &v) {
        if (const auto *c = std::get_if<ignil::Const>(&v))
            info.known.push_back(c->value);
        else
            info.hasIndirect = true;
    };

    if (last.opcode == ignil::Opcode::JMP && !last.srcs.empty()) {
        pushValue(last.srcs[0]);
    } else if (last.opcode == ignil::Opcode::CJMP && last.srcs.size() >= 3) {
        pushValue(last.srcs[1]); // taken
        pushValue(last.srcs[2]); // fallthrough
    }
    // CALL is not a block terminator for the CFG — fall-through to the
    // next instruction is the only statically-known successor.
    return info;
}
```

`buildPredecessorMap` must be updated to use `info.known` instead of
the plain vector. Nothing else changes — indirect-target blocks simply
never get an entry in the pred-map (they remain unresolved until the
switch analyzer runs).

---

### 6.2 — Z3 lowerer: `SliceExprZ3`

The lowerer converts a `slice::Expr` tree into a `z3::expr` bitvector
formula. All integer values are represented as Z3 bitvectors of the
appropriate width. The lowerer is stateful: free symbolic variables
(generated for `SymReg` nodes) are cached so the same register produces
the same Z3 symbol across multiple calls within one query.

#### Files

```
include/dragon/analysis/SliceExprZ3.hpp
lib/analysis/SliceExprZ3.cpp
```

#### Class sketch

```cpp
// include/dragon/analysis/SliceExprZ3.hpp
#pragma once

#include <dragon/analysis/SliceExpr.hpp>
#include <z3++.h>
#include <unordered_map>
#include <string>

namespace dragon::slice {

/// Lowers a SliceExpr tree into a Z3 bitvector expression.
///
/// SymReg nodes become unconstrained Z3 bitvector constants.
/// The same SymReg (same offset + width) always maps to the same Z3 symbol,
/// so constraints can be shared across multiple lowered expressions.
///
/// Usage:
///   z3::context ctx;
///   SliceExprZ3 lowerer(ctx);
///   z3::expr formula = lowerer.lower(expr);
class SliceExprZ3 {
  public:
  explicit SliceExprZ3(z3::context &ctx);

  /// Lower a SliceExpr into a Z3 bitvector expression.
  /// The width of the returned expression matches the width of the root node.
  [[nodiscard]] z3::expr lower(const Expr &e) const;

  /// Return the Z3 symbol for a given symbolic register (creates it lazily).
  [[nodiscard]] z3::expr symFor(const SymReg &r) const;

  /// Clear the symbol cache (call between independent queries).
  void reset();

  private:
  z3::context &ctx_;

  // Cache: "<name>:i<width>" or "reg[<offset>]:i<width>" → z3::expr
  mutable std::unordered_map<std::string, z3::expr> symCache_;
};

} // namespace dragon::slice
```

#### Lowering rules

| `SliceExpr` node | Z3 bitvector translation |
|---|---|
| `Const{v, w}` | `ctx.bv_val(v, w)` |
| `SymReg{r}` | `ctx.bv_const("<r.name>", r.width)` (cached) |
| `BinOp{ADD, l, r}` | `lower(l) + lower(r)` |
| `BinOp{SUB, l, r}` | `lower(l) - lower(r)` |
| `BinOp{MUL, l, r}` | `lower(l) * lower(r)` |
| `BinOp{AND, l, r}` | `lower(l) & lower(r)` |
| `BinOp{OR, l, r}` | `lower(l) \| lower(r)` |
| `BinOp{XOR, l, r}` | `lower(l) ^ lower(r)` |
| `BinOp{SHL, l, r}` | `z3::shl(lower(l), lower(r))` |
| `BinOp{SHR, l, r}` | `z3::lshr(lower(l), lower(r))` |
| `BinOp{SAR, l, r}` | `z3::ashr(lower(l), lower(r))` |
| `BinOp{SDIV, l, r}` | `lower(l) / lower(r)` (Z3 signed bvsdiv) |
| `BinOp{UDIV, l, r}` | `z3::udiv(lower(l), lower(r))` |
| `BinOp{SMOD, l, r}` | `z3::srem(lower(l), lower(r))` |
| `BinOp{UMOD, l, r}` | `z3::urem(lower(l), lower(r))` |
| `BinOp{EQ, l, r}` | `z3::ite(lower(l) == lower(r), ctx.bv_val(1,1), ctx.bv_val(0,1))` |
| `BinOp{ULT/ULE/UGT/UGE, l, r}` | `z3::ult / z3::ule / z3::ugt / z3::uge` wrapped in `ite` |
| `BinOp{SLT/SLE/SGT/SGE, l, r}` | `z3::slt / z3::sle / ...` wrapped in `ite` |
| `UnaryOp{NEG, v}` | `-lower(v)` |
| `UnaryOp{NOT, v}` | `~lower(v)` |
| `UnaryOp{ZEXT, v}` | `z3::zext(lower(v), targetWidth - srcWidth)` |
| `UnaryOp{SEXT, v}` | `z3::sext(lower(v), targetWidth - srcWidth)` |
| `UnaryOp{TRUNC, v}` | `lower(v).extract(targetWidth-1, 0)` |
| `Load{addr, w}` | `ctx.bv_const("mem_<hash(addr)>", w)` — uninterpreted memory read |
| `Undef` | `ctx.bv_const("undef", 64)` — fresh unconstrained symbol |

**Width tracking for extension / truncation.** `ZEXT` and `SEXT` need to
know the target width. Since `Expr` does not currently carry a width field,
the lowerer infers it from the parent op's `dst.width`. An alternative is
to add an explicit `width` field to `UnaryOp` (mirrors the `Load` node
which already carries `width`). The cleaner approach is to add the field:

```cpp
struct UnaryOp {
    ignil::Opcode op;
    std::shared_ptr<Expr> operand;
    ignil::Width resultWidth;   // needed for ZEXT, SEXT, TRUNC
};
```

This is a small breaking change to `buildFromOp` in `BackwardSlicer.cpp`
where `UnaryOp` is constructed — the result width must be read from
`op.dst` (which the slicer already has access to).

#### Example

```cpp
z3::context ctx;
dragon::slice::SliceExprZ3 lowerer(ctx);

// slice::Expr for: ADD(RAX:i64, 0x8:i64)
auto formula = lowerer.lower(expr);
// → (bvadd RAX_i64 #x0000000000000008)

// With a constraint: RAX ∈ [0, 4]
z3::solver solver(ctx);
z3::expr rax = lowerer.symFor(raxSymReg);
solver.add(z3::uge(rax, ctx.bv_val(0, 64)));
solver.add(z3::ule(rax, ctx.bv_val(4, 64)));
```

---

### 6.3 — Value enumeration

`enumerateValues` finds all concrete values an expression can take under
a set of constraints, up to a caller-specified maximum. It is the
building block for switch-case extraction.

#### API

```cpp
// include/dragon/analysis/ValueEnumerator.hpp
#pragma once

#include <dragon/analysis/SliceExpr.hpp>
#include <dragon/analysis/SliceExprZ3.hpp>
#include <z3++.h>
#include <cstdint>
#include <functional>
#include <vector>

namespace dragon::slice {

struct EnumeratorConfig {
    std::size_t maxValues    = 256;   // abort after this many solutions
    bool        sorted       = true;  // sort results before returning
};

/// Enumerate all concrete 64-bit values that `expr` can take given
/// the extra `constraints` (already expressed as Z3 assertions).
///
/// Each call to Z3 produces one model, then adds a blocking clause
/// (expr != found_value) before asking for the next.  The loop ends
/// when the solver returns UNSAT or maxValues is reached.
///
/// Returns an empty vector when the expression is unsatisfiable under
/// the given constraints, or when the expression is fully concrete
/// (Const node) — in the latter case the single constant value is
/// returned directly without calling Z3.
[[nodiscard]] std::vector<std::uint64_t>
enumerateValues(const Expr &expr,
                z3::context &ctx,
                const std::vector<z3::expr> &constraints = {},
                const EnumeratorConfig &cfg = {});

/// Convenience: solve for a single concrete value.
/// Returns nullopt if unsatisfiable or if the expression is not
/// uniquely determined (i.e. more than one model exists).
[[nodiscard]] std::optional<std::uint64_t>
solveUnique(const Expr &expr,
            z3::context &ctx,
            const std::vector<z3::expr> &constraints = {});

} // namespace dragon::slice
```

#### Implementation sketch

```cpp
std::vector<std::uint64_t>
dragon::slice::enumerateValues(const Expr &expr,
                               z3::context &ctx,
                               const std::vector<z3::expr> &constraints,
                               const EnumeratorConfig &cfg) {

    // Fast path: constant expression needs no solver.
    if (const auto *c = std::get_if<Const>(&expr.data))
        return {c->value};

    SliceExprZ3 lowerer(ctx);
    z3::expr formula = lowerer.lower(expr);
    z3::solver solver(ctx);

    for (const auto &c : constraints)
        solver.add(c);

    std::vector<std::uint64_t> results;

    while (results.size() < cfg.maxValues) {
        if (solver.check() != z3::sat)
            break;

        z3::model m = solver.get_model();
        // Evaluate the expression in the current model.
        z3::expr val = m.eval(formula, /*model_completion=*/true);
        std::uint64_t concrete = val.get_numeral_uint64();
        results.push_back(concrete);

        // Block this solution so the next call finds a different one.
        solver.add(formula != ctx.bv_val(concrete, formula.get_sort().bv_size()));
    }

    if (cfg.sorted)
        std::sort(results.begin(), results.end());

    return results;
}
```

---

### 6.4 — Switch detection and analysis

#### What a compiled switch looks like in IGNIL

A compiler lowers a dense `switch` statement to a jump table. The
typical x86_64 pattern is:

```
; Bounds check (guards the switch)
0x1000:  cmp   ecx, 5           ; compare index with max case
0x1003:  ja    0x1040           ; if index > 5, jump to default

; Table dispatch
0x1009:  movsxd rax, ecx        ; sign-extend index to 64-bit
0x100C:  lea    rcx, [rip + table_offset]   ; RCX = base of jump table
0x1013:  mov    rax, [rcx + rax*8]          ; load table[index]
0x1017:  jmp    rax
```

After IGNIL lifting:

```
Block @ 0x1000  (bounds check)
  t0:i1 = UGT(ECX:i32, 0x5:i32)
  CJMP(t0:i1, 0x1040:i64, 0x1009:i64)

Block @ 0x1009  (dispatch)
  t0:i64 = SEXT(ECX:i32)         ; movsxd
  t1:i64 = ADD(RIP:i64, <off>)   ; lea: table base
  t2:i64 = SHL(t0:i64, 0x3:i8)  ; *8 scale
  t3:i64 = ADD(t1:i64, t2:i64)  ; table + index*8
  t4:i64 = LOAD(t3:i64)          ; load entry from table
  JMP(t4:i64)                    ; indirect jump
```

The backward slicer, starting from `t4` (the JMP target), already
produces the full `SliceExpr` tree:

```
LOAD(
  ADD(
    ADD(RIP:i64, Const{table_off}:i64),
    SHL(SEXT(ECX:i32), Const{3}:i8)
  )
)
```

What is missing is:
1. Detecting this pattern.
2. Harvesting the bound `index ≤ 5` from the predecessor `CJMP`.
3. Using Z3 to enumerate the 6 possible table entry addresses, resolving
   the `RIP` symbol to its concrete value.

#### `SwitchAnalyzer` class

```cpp
// include/dragon/analysis/SwitchAnalyzer.hpp
#pragma once

#include <dragon/analysis/BackwardSlicer.hpp>
#include <dragon/analysis/SliceExprZ3.hpp>
#include <dragon/analysis/ValueEnumerator.hpp>
#include <dragon/disassembler/Graph.hpp>
#include <z3++.h>
#include <cstdint>
#include <optional>
#include <vector>

namespace dragon {

/// Describes a resolved switch table.
struct SwitchInfo {
    std::uint64_t dispatchBlockAddr;   ///< Block containing the indirect JMP
    std::uint64_t tableBaseAddr;       ///< Resolved address of the jump table
    std::vector<std::uint64_t> targets; ///< Resolved jump targets (one per case)
};

/// Identifies switch patterns in a Graph and resolves their targets.
///
/// The analyzer scans every IGNIL block for the JMP(Temp ← LOAD(addr_expr))
/// pattern, then:
///   1. Backward-slices `addr_expr` to get the full address formula.
///   2. Searches the unique predecessor chain for a guarding CJMP that
///      bounds the switch index.
///   3. Lowers the index formula + bound constraint to Z3 and enumerates
///      all possible table-entry addresses.
///
/// Memory contents are not directly available to the analyzer — the caller
/// must provide a `readMemory` callback so the analyzer can dereference the
/// table entries (each entry is a 64-bit pointer on x86_64).
class SwitchAnalyzer {
  public:
  using MemReader = std::function<std::optional<std::uint64_t>(std::uint64_t addr)>;

  explicit SwitchAnalyzer(const Graph &graph,
                          MemReader readMemory,
                          int maxBlocks = 5,
                          std::size_t maxCases = 256);

  /// Scan every block in the graph and return all resolved switches.
  [[nodiscard]] std::vector<SwitchInfo> analyze() const;

  private:
  // Attempt to resolve one indirect-jump block as a switch.
  // Returns nullopt if the pattern is not recognised.
  [[nodiscard]] std::optional<SwitchInfo>
  tryResolve(std::uint64_t blockAddr) const;

  // Walk the unique predecessor chain of `blockAddr` looking for a CJMP
  // whose condition involves the same symbolic variable as `indexExpr`.
  // Returns the Z3 bound constraint, or nullopt if none found.
  [[nodiscard]] std::optional<z3::expr>
  findBoundConstraint(std::uint64_t blockAddr,
                      const slice::Expr &indexExpr,
                      z3::context &ctx,
                      const slice::SliceExprZ3 &lowerer) const;

  const Graph &graph_;
  MemReader readMemory_;
  BackwardSlicer slicer_;
  std::size_t maxCases_;
};

} // namespace dragon
```

#### Analysis algorithm (step-by-step)

```
For each block B in the graph:

  1. Check if B's terminal op is JMP(Temp{N}).
     If not, skip.

  2. Walk ops of B backward from the JMP to find the defining op for Temp{N}.
     If its opcode is not LOAD, skip (not a memory-indirect JMP — already
     handled by the regular indirect-register JMP path).

  3. Slice the LOAD's address operand: addrExpr = slicer.slice(loadSrc, B, g)
     The result is typically:
       ADD(ADD(RIP, table_offset), SHL(SEXT(index_reg), 3))

  4. Identify the "free variable" in addrExpr.
     A free variable is any SymReg in the tree that is not RIP.
     If there are zero or more than one free variables, abort (too complex).
     Call it indexSym.

  5. Search the predecessor chain of B (up to maxBlocks) for a CJMP whose
     condition involves a comparison against indexSym.
     Typical form in IGNIL: t = UGT(index_reg, max_val) → CJMP(t, default, B)
     Extract the bound: index ∈ [0, max_val].

  6. Instantiate Z3 context, lower addrExpr to a Z3 formula.
     Add the bound constraint: 0 ≤ indexSym ≤ max_val.
     Concretise RIP to its known address (the address of the `lea` instruction
     + instruction size + the `table_offset` immediate).

  7. Call enumerateValues(addrExpr, ctx, {bound}) to get the list of
     table entry addresses (one per case: addr_of_table[0], ..., addr_of_table[N]).

  8. For each table-entry address, call readMemory(addr) to dereference the
     8-byte pointer and get the actual branch target.
     Collect into SwitchInfo::targets.

  9. Return the SwitchInfo.
```

#### Harvesting the bound constraint (step 5)

The predecessor of the dispatch block is the bounds-check block. Its
terminal op is typically:

```
CJMP( UGT(index_reg, max_val), default_block, dispatch_block )
```

The condition is `UGT(index_reg, max_val)`. Since the CJMP's
**not-taken** branch leads to the dispatch block, the constraint we want
is the negation: `index ≤ max_val` (i.e. `NOT UGT`, which is `ULE`).

Algorithm:

```
1. For each predecessor P of B:

   a. Find P's terminal CJMP.
   b. Check if the not-taken branch (srcs[2]) equals B's address.
   c. Backward-slice the condition (srcs[0]) from P.
   d. If the slice is BinOp{UGT, indexExpr, Const{max}}, the constraint is
      z3::ule(lowerIndex, ctx.bv_val(max, w)).
   e. If the slice is BinOp{ULT, Const{0}, indexExpr} ... (other forms, handle symmetrically).

2. If none of the predecessors yields a usable bound, return nullopt.
   The switch may still be partially resolved if the caller provides
   an explicit bound through the EnumeratorConfig::maxValues cap.
```

In real binaries, the compiler often emits the bound check as
`jb` / `ja` (unsigned below/above), which maps to `ULT` / `UGT` in IGNIL.
The table below lists all cases that should be handled:

| CJMP condition | Constraint on index (not-taken = dispatch) |
|---|---|
| `UGT(i, N)` — taken is default | `i ∈ [0, N]` |
| `UGE(i, N+1)` — variant form | `i ∈ [0, N]` |
| `ULT(N+1, i)` — inverted operands | `i ∈ [0, N]` |
| `EQ(i, 0)` — single-case table | `i = 0` |

---

### 6.5 — Connecting the pieces: complete switch-resolution flow

The full pipeline for a binary containing a switch table:

```
1. Disassemble the binary → Graph (fills basic blocks + IGNIL blocks)

2. BackwardSlicer  ←  used internally by SwitchAnalyzer to build SliceExprs

3. SwitchAnalyzer::analyze()
   → returns vector<SwitchInfo> with resolved targets

4. For each SwitchInfo:
   a. Add each target to blocks_q so the disassembler continues
      into the switch cases (IGNIL now knows the CFG edges)
   b. Optionally annotate the dispatch block with its targets for
      display in a disassembly listing
```

C++ usage sketch:

```cpp
#include <dragon/analysis/SwitchAnalyzer.hpp>

// Assume `binary` is a std::span<const std::byte> loaded from disk,
// mapped at `imageBase`.
dragon::SwitchAnalyzer analyzer(
    graph,
    // MemReader: given an address, return the 8-byte pointer stored there
    [&](std::uint64_t addr) -> std::optional<std::uint64_t> {
        if (addr < imageBase || addr + 8 > imageBase + binary.size())
            return std::nullopt;
        std::uint64_t val;
        std::memcpy(&val, binary.data() + (addr - imageBase), 8);
        return val;
    }
);

std::vector<dragon::SwitchInfo> switches = analyzer.analyze();

for (const auto &sw : switches) {
    std::cout << std::format("Switch @ 0x{:x}: {} cases\n",
                             sw.dispatchBlockAddr, sw.targets.size());
    for (std::uint64_t target : sw.targets)
        std::cout << std::format("  -> 0x{:x}\n", target);
}
```

---

### 6.6 — CMake changes

The Z3 package must be found before the new files are compiled. Add to
the top-level `CMakeLists.txt`:

```cmake
find_package(Z3 REQUIRED CONFIG)
# Z3_LIBRARIES and Z3_INCLUDE_DIRS are set by Z3Config.cmake
```

Add the new source files to `lib/CMakeLists.txt`:

```cmake
target_sources(libdragon PRIVATE
    analysis/SliceExprZ3.cpp       # new
    analysis/ValueEnumerator.cpp   # new
    analysis/SwitchAnalyzer.cpp    # new
)

target_link_libraries(libdragon PRIVATE z3::libz3)
```

---

### 6.7 — Testing the new components

#### Test: Z3 lowerer resolves a constant expression

```cpp
TEST_CASE("SliceExprZ3 — constant expression is concrete") {
    // Expr: ADD(Const{0x3000, 64}, Const{8, 64})
    slice::Expr expr{slice::BinOp{
        ignil::Opcode::ADD,
        std::make_shared<slice::Expr>(slice::Const{0x3000, 64}),
        std::make_shared<slice::Expr>(slice::Const{8, 64})
    }};

    z3::context ctx;
    slice::SliceExprZ3 lowerer(ctx);
    z3::solver solver(ctx);
    z3::expr formula = lowerer.lower(expr);
    solver.add(formula == ctx.bv_val(0x3008, 64));

    REQUIRE(solver.check() == z3::sat);
}
```

#### Test: enumerateValues with a bound constraint

```cpp
TEST_CASE("enumerateValues — bounded index produces N solutions") {
    // Expr: SHL(SymReg{RCX, i64}, Const{3}) — index * 8
    ignil::Reg rcx{8, 64, "RCX"};
    slice::Expr expr{slice::BinOp{
        ignil::Opcode::SHL,
        std::make_shared<slice::Expr>(slice::SymReg{rcx}),
        std::make_shared<slice::Expr>(slice::Const{3, 8})
    }};

    z3::context ctx;
    slice::SliceExprZ3 lowerer(ctx);

    // Constraint: RCX ∈ [0, 3]
    z3::expr rcxSym = lowerer.symFor(slice::SymReg{rcx});
    std::vector<z3::expr> constraints = {
        z3::uge(rcxSym, ctx.bv_val(0, 64)),
        z3::ule(rcxSym, ctx.bv_val(3, 64))
    };

    auto values = slice::enumerateValues(expr, ctx, constraints);
    // Expected: { 0, 8, 16, 24 }  (i.e. 0*8, 1*8, 2*8, 3*8)
    REQUIRE(values.size() == 4);
    REQUIRE(values[0] == 0);
    REQUIRE(values[1] == 8);
    REQUIRE(values[2] == 16);
    REQUIRE(values[3] == 24);
}
```

#### Test: SwitchAnalyzer detects a 4-case table

```cpp
TEST_CASE("SwitchAnalyzer — 4-case jump table") {
    // Encode in bytes:
    //   0x1000: cmp ecx, 3         ; 83 F9 03
    //   0x1003: ja  0x1020         ; 77 1B  (default / out-of-range)
    //   0x1005: movsxd rax, ecx    ; 48 63 C1
    //   0x1008: lea rcx, [rip+15]  ; 48 8D 0D 0F 00 00 00  (table @ 0x1014)
    //   0x100F: mov rax, [rcx+rax*8] ; 48 8B 04 C1
    //   0x1013: jmp rax            ; FF E0
    //   0x1015..0x1034: 4 × 8-byte entries in the jump table

    // ... set up bytes, disassemble, run SwitchAnalyzer ...

    REQUIRE(switches.size() == 1);
    REQUIRE(switches[0].targets.size() == 4);
}
```

---

### 6.8 — Limitations and future work

| Limitation | Mitigation / future fix |
|---|---|
| Non-dense switch tables (sparse cases with holes) | Z3 enumeration still works — holes produce entries equal to the default block; filter by checking each target is a real block start |
| Multi-level indirection (`jmp [rbx + rax*8]` where rbx itself is loaded) | Extend backward slicer to follow Load nodes; `Load` in `SliceExpr` already exists, only the Z3 lowerer needs to model memory reads as uninterpreted functions |
| Compiler-generated range reduction (index -= low_case) | Slice-based approach already captures the arithmetic; add a check for `SUB(index, Const)` before the SHL |
| Jump tables in read-only data sections vs. inline after code | `MemReader` callback abstracts over this — the caller decides how to map addresses |
| Path-sensitive constraints (nested ifs before the bounds check) | Extend `findBoundConstraint` to walk more than one predecessor; collect a conjunction of all `CJMP` guards along the unique path |
| 32-bit relative entries (common in PIC code: table contains `target - table_base`) | Detect 32-bit LOAD width, `SEXT` the result, `ADD` the table base back; the backward slice will naturally encode this if the lifter emits the right ops |
