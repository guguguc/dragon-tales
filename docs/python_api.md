# Python API

The Python API wraps the C shim via [cffi](https://cffi.readthedocs.io/).
Build the C shim first (`libdragon_c.so` must exist in `build/c_shim/`),
then import the module:

```python
import sys
sys.path.insert(0, 'python')
import dragon
```

All three main objects (`Configuration`, `Disassembler`, `Assembler`) support the
context-manager protocol for deterministic cleanup.

---

## Configuration

```python
cfg = dragon.Configuration(
    syntax   = dragon.Syntax.INTEL,           # default
    strategy = dragon.Strategy.LINEAR_SWEEP,  # default
    cpu      = '',                            # default — LLVM "generic" baseline
    features = '',                            # default — no extra features
)

print(cfg)          # <Configuration syntax=0 strategy=0>
print(cfg.syntax)   # 0  (INTEL)
print(cfg.strategy) # 0  (LINEAR_SWEEP)
print(cfg.cpu)      # ''
print(cfg.features) # ''
```

If you omit `config` when constructing a `Disassembler` or `Assembler`,
a default `Configuration` is created automatically.

### Targeting a specific CPU or ISA revision

`cpu` and `features` are forwarded to LLVM's `MCSubtargetInfo`. An empty
string uses the "generic" baseline for the target triple, which may omit
optional ISA extensions. Both are readable and writable properties.

```python
# ARM32 — enable BX/BLX (ARMv4T, absent from the generic ARM baseline)
cfg = dragon.Configuration(cpu="arm926ej-s")
dis = dragon.Disassembler(dragon.Architecture.ARM32, cfg)

# ARM32 — same effect using a feature flag instead of a CPU name
cfg = dragon.Configuration(features="+v4t")
dis = dragon.Disassembler(dragon.Architecture.ARM32, cfg)

# ARM32 — ARMv7-A with NEON
cfg = dragon.Configuration(features="+v7,+neon")

# x86-64 — Skylake micro-architecture
cfg = dragon.Configuration(cpu="skylake")

# RISC-V 64 — multiply, atomics and compressed extensions
cfg = dragon.Configuration(features="+m,+a,+c")

# Properties are writable after construction
cfg = dragon.Configuration()
cfg.cpu      = "cortex-a8"
cfg.features = "+neon"
```

**cpu examples by architecture**

| Architecture | `cpu` value | Enables |
|---|---|---|
| ARM32 | `"arm926ej-s"` | ARMv5TEJ — BX, BLX |
| ARM32 | `"cortex-a8"` | ARMv7-A, Thumb2, NEON, VFPv3 |
| ARM64 | `"cortex-a53"` | AArch64 baseline |
| ARM64 | `"apple-m1"` | AArch64 + Apple extensions |
| x86-64 | `"skylake"` | AVX2, BMI2, AES |
| x86-64 | `"znver3"` | AMD Zen 3 |
| RISC-V 64 | `"sifive-u74"` | RV64GC |

**features examples**

| String | Meaning |
|---|---|
| `"+v4t"` | ARM32: add BX (ARMv4T) |
| `"+v7,+neon"` | ARM32: ARMv7 + NEON |
| `"+sve"` | ARM64: Scalable Vector Extension |
| `"+avx2"` | x86: AVX2 |
| `"+m,+a,+c"` | RISC-V: multiply, atomics, compressed |
| `"+f,+d"` | RISC-V: single- and double-precision FP |

---

## Disassembler

### Basic usage

```python
code = bytes([0x90, 0xC3])   # nop; ret

cfg = dragon.Configuration(syntax=dragon.Syntax.INTEL)
dis = dragon.Disassembler(arch=dragon.Architecture.X86_64, config=cfg)

graph = dis.disassemble(code, base_address=0x1000)

for insn in graph.instructions():
    print(f"0x{insn.address:x}  {insn.disassembly}")
# 0x1000  nop
# 0x1001  ret
```

### Using the context manager

```python
cfg = dragon.Configuration()
with dragon.Disassembler(dragon.Architecture.X86_64, cfg) as dis:
    with dis.disassemble(code, 0x1000) as graph:
        for insn in graph.instructions():
            print(hex(insn.address), insn.mnemonic, insn.operands)
```

### Instruction properties

```python
for insn in graph.instructions():
    print(insn.address)          # int
    print(insn.size)             # int (bytes)
    print(insn.mnemonic)         # str
    print(insn.operands)         # str
    print(insn.disassembly)      # mnemonic + operands
    print(insn.bytes.hex())      # raw encoding, e.g. "90"
    print(insn.pattern)          # wildcard pattern string
    print(insn.chromosome_mask)  # bytes

    print(insn.is_call)
    print(insn.is_jump)
    print(insn.is_return)
    print(insn.is_conditional)
    print(insn.is_block_start)
    print(insn.is_function_start)
    print(insn.edges)

    print(insn.branches)   # list of target addresses
    print(insn.callees)    # list of callee addresses
```

### Recursive traversal

```python
cfg = dragon.Configuration(strategy=dragon.Strategy.RECURSIVE_TRAVERSAL)
dis = dragon.Disassembler(dragon.Architecture.X86_64, cfg)
graph = dis.disassemble(code, 0x1000)
```

### Analysis: blocks, functions and IGNIL

`disassemble()` gives you the flat instruction listing. `analyze()` takes the
same arguments but goes further — it runs block and function discovery and
lifts each block to IGNIL, so the `Graph` it returns has everything the
backward slicer, the LLVM lifter and symbolic execution need.

```python
graph = dis.analyze(code, base_address=0x1000)
```

Use `disassemble()` when you only want the listing; use `analyze()` whenever a
later step needs blocks, functions or IGNIL.

### Trace lifting

`Disassembler.lift_trace()` lifts an arbitrary linear sequence of
already-decoded instructions straight to IGNIL — e.g. a captured execution
trace (Unicorn/QBDI/Frida/Intel PT) that isn't claimed to form a single
valid basic block or a coherent CFG. It bypasses `disassemble()`'s
CFG/function/block-validity analysis entirely: each instruction is lifted
independently and the results concatenated in order, with no synthesized
fall-through terminator.

```python
graph = dis.disassemble(code, 0x1000)
insns = graph.instructions()   # or hand-pick/reorder — need not be contiguous

with dis.lift_trace(insns) as block:
    print(block.to_string())
```

The returned `IGNILBlock` is **owned** — unlike `Graph.get_ignil_block()`'s
borrowed one — and gets destroyed on `__del__`/context-manager exit. It's
still the same `IGNILBlock` class either way; only the `owned` flag differs
internally.

---

## Graph: blocks and functions

```python
# Look up a single instruction by address
insn = graph.get_instruction(0x1000)
if insn:
    print(insn.disassembly)

# Block addresses that were identified
for addr in graph.block_addresses():
    print(f"block @ {hex(addr)}")

# Inspect a single block
bb = graph.get_block(0x1000)
if bb.is_valid:
    print(f"size:       {bb.size} instructions")
    print(f"byte size:  {bb.byte_size}")
    print(f"terminator: {hex(bb.terminator_address)}")
    for insn in bb.instructions():
        print(" ", insn.disassembly)
    for succ in bb.successors():
        print(f"  successor -> {hex(succ)}")

# Function addresses that were identified
for addr in graph.function_addresses():
    print(f"function @ {hex(addr)}")

# Inspect a single function
fn = graph.get_function(0x1000)
if fn.is_valid:
    print(f"blocks:       {fn.num_blocks}")
    print(f"instructions: {fn.num_instructions}")
    print(f"byte size:    {fn.byte_size}")
    print(f"cyclomatic:   {fn.cyclomatic_complexity}")
```

---

## Assembler

```python
cfg = dragon.Configuration(syntax=dragon.Syntax.INTEL)
asm = dragon.Assembler(arch=dragon.Architecture.X86_64, config=cfg)

if not asm.is_valid:
    raise RuntimeError("assembler init failed")

raw = asm.assemble("nop\nret\n")
print(raw.hex())   # 90c3
```

### Round-trip example

```python
source = "push rbp\nmov rbp, rsp\npop rbp\nret\n"

cfg = dragon.Configuration()
asm = dragon.Assembler(dragon.Architecture.X86_64, cfg)
raw = asm.assemble(source)

dis = dragon.Disassembler(dragon.Architecture.X86_64, cfg)
graph = dis.disassemble(raw, base_address=0x0)

for insn in graph.instructions():
    print(f"0x{insn.address:x}  {insn.disassembly}")
```

### AT&T syntax

```python
cfg = dragon.Configuration(syntax=dragon.Syntax.ATT)
asm = dragon.Assembler(dragon.Architecture.X86_64, cfg)
raw = asm.assemble("nop\nret\n")
```

---

## Loading a binary

`LoadedImage` parses an ELF or PE/COFF file — or in-memory bytes — into its
sections and segments at their virtual addresses, the entry point, the image
base, the symbol table, and the architecture, all detected from the header.
You never name the architecture: it comes from the file.

```python
img = dragon.LoadedImage.load_file('a.out')
print(hex(img.image_base), 'arch', img.architecture)
print('entry', hex(img.entry) if img.entry is not None else None)

for s in img.sections():
    print(s)        # <Section '.text' @0x1139 size=0x1a2 r-x>

graph = img.disassemble()       # every executable section -> a populated Graph
print(len(graph), 'instructions')
```

Load from bytes you already hold with `LoadedImage.load_bytes(data)`. Both
classmethods raise `ValueError` with the loader's message on failure, and the
image is a context manager:

```python
with dragon.LoadedImage.load_file('a.out') as img:
    graph = img.disassemble()
```

### Sections, segments and symbols

`sections()` and `segments()` both return `Section` objects (`name`,
`address`, `virtual_size`, `readable`, `writable`, `executable`, `data`).
Sections are the linker's view; segments are the ELF `PT_LOAD` regions the
system loader actually maps, named `LOAD0`, `LOAD1`, … — the only layout left
to work with once a protector strips the section headers. `segments()` is
empty for PE.

```python
for seg in img.segments():
    print(seg)      # <Section 'LOAD0' @0x400000 size=0x1000 r-x>

for sym in img.symbols():
    if sym.exported:
        print(hex(sym.address), sym.name, sym.kind)
```

`read_virtual(address, size)` reads straight out of the mapped address space,
or returns `None` if the range is unmapped — handy for following a pointer the
disassembler turned up without caring which section it lands in.

```python
data = img.read_virtual(img.image_base, 4)
print(data.hex() if data else 'unmapped')
```

### disassemble()

`disassemble(config=None)` disassembles every executable section into a
`Graph` built for the detected architecture, so a file reaches analysis in one
call. Pass a `Configuration` to control syntax or strategy; omit it for the
defaults.

| Member | Type | Notes |
|---|---|---|
| `LoadedImage.load_file(path)` | `LoadedImage` | Classmethod; raises `ValueError` on failure |
| `LoadedImage.load_bytes(data)` | `LoadedImage` | Classmethod; raises `ValueError` on failure |
| `format` | `Format` | `ELF`, `PE`, or `UNKNOWN` |
| `architecture` | `Architecture` | Detected from the header |
| `is_64bit` | `bool` | |
| `image_base` | `int` | |
| `entry` | `int` or `None` | `None` when the image has no entry point |
| `sections()` | `list[Section]` | |
| `segments()` | `list[Section]` | ELF `PT_LOAD` regions; empty for PE |
| `symbols()` | `list[Symbol]` | |
| `read_virtual(address, size)` | `bytes` or `None` | `None` if the range is unmapped |
| `disassemble(config=None)` | `Graph` | Every executable section |

`Section` and `Symbol` are plain data objects; `Format` and `SymbolKind` are
the enums listed under [Enum reference](#enum-reference).

---

## IGNIL blocks

`Disassembler.analyze()` (not `disassemble()`) populates IGNIL blocks in the
graph. Retrieve one with `graph.get_ignil_block(address)`.

```python
dis   = dragon.Disassembler(dragon.Architecture.X86_64)
# nop; cmp rax, rbx; ret
code  = bytes([0x90, 0x48, 0x39, 0xD8, 0xC3])
graph = dis.analyze(code, base_address=0x1000)

ib = graph.get_ignil_block(0x1000)   # None if no IGNIL block at that address
if ib:
    print(ib.to_string())
    # IGNILBlock @ 0x1000
    #   t0:i64 = SUB(RAX:i64, RBX:i64)  ; @0x1001
    #   ...

    # Individual ops (each yields address, opcode int, index)
    for addr, opc, idx in ib.ops():
        print(f"[{idx}] @{hex(addr)}  {dragon.IGNILOpcode.name(opc)}")
        print(ib.op_to_string(idx))
```

`IGNILBlock` is a borrowed view — it is valid as long as the owning graph
is alive; no `__exit__` / destroy needed.

### Peephole simplification

`simplify()` runs the peephole simplifier to a fixed point: constant
folding/propagation, algebraic identity/annihilator elimination, no-op
width-conversion elimination, and dead-Temp elimination. It is block-local
only — it never crosses into predecessor/successor blocks, and never
removes a `Reg`-defining op even if apparently unused within the block (a
`Reg` may be live-out).

```python
simplified, stats = ib.simplify()   # max_iterations=0 selects the default (8)
print(stats)
# <SimplifyStats constants_folded=2 identities_applied=1 ops_removed=3 iterations=2>
print(simplified.to_string())
```

`simplified` is a new, independently owned `IGNILBlock` — `ib` is left
untouched and both must be cleaned up independently (context manager or GC).

### Dead-store elimination

`dead_store_eliminate(arch, live_out=None)` removes dead register and flag
stores by byte-precise backward liveness: a value written to a register that
is overwritten before it is ever read, and is not live on exit, is dropped.
Unlike `simplify()` this *does* remove `Reg`-defining ops — which is what
collapses VM-protector junk — so an instruction whose only live effect was the
removed write disappears entirely. Side-effecting ops
(`STORE`/`CALL`/`JMP`/`CJMP`/`RET`) are never removed.

```python
cleaned, removed = ib.dead_store_eliminate(dragon.Architecture.X86_64)
print(f"{removed} ops removed")
print(cleaned.to_string())
```

`arch` selects the register file used to resolve which bytes a 32-bit write
zero-extends over, so pass the architecture the block was lifted for.
`live_out` is an iterable of `(offset, width)` pairs — the first two fields of
the `x86` / `arm` descriptors — naming the registers observable after the
block. `None` (the default) assumes everything is live on exit, which removes a
store only when it is provably overwritten within the block and so needs no ABI
knowledge; passing a precise list (e.g. just the ABI return and callee-saved
registers for a `RET`-terminated block) allows more aggressive elimination,
with correctness then resting on the list being sound. The returned block is
new and independently owned.

### Instructions with no semantics

`unlifted()` returns the machine addresses of the instructions the lifter had
no semantics for, in order. Their results are `UNDEF`, so nothing downstream is
silently wrong — but an `UNDEF` that later dies is invisible, and an
instruction whose only effect is a memory write leaves no op at all. Check it
when the block has to be a complete account of the code, e.g. before trusting a
symbolic run of it. `simplify()` and `dead_store_eliminate()` carry the list
over.

```python
missing = ib.unlifted()
if missing:
    print('no semantics for:', [hex(a) for a in missing])
```

---

## x86 register constants

`dragon.x86` exposes every x86/x86-64 register as a 3-tuple
`(offset, width, name)` that can be splatted directly into
`BackwardSlicer.slice_reg()`:

```python
dragon.x86.RAX   # (0,   64, 'RAX')
dragon.x86.ZF    # (139,  8, 'ZF')
dragon.x86.AH    # (1,    8, 'AH')

# Available groups
# 64-bit: RAX RCX RDX RBX RSP RBP RSI RDI R8..R15 RIP
# 32-bit: EAX ECX .. R15D
# 16-bit: AX CX .. R15W
# 8-bit low: AL CL .. R15B
# 8-bit high: AH CH DH BH
# Flags (8-bit): CF PF AF ZF SF OF DF
```

---

## AArch64 register constants

`dragon.arm` mirrors `dragon.x86` for AArch64 — every register as a 3-tuple
`(offset, width, name)`:

```python
dragon.arm.X0   # (0,   64, 'X0')
dragon.arm.ZF   # (785,  8, 'ZF')
dragon.arm.W0   # (0,   32, 'W0')   -- 32-bit view of X0
dragon.arm.FP   # (232, 64, 'FP')  -- alias for X29
dragon.arm.LR   # (240, 64, 'LR')  -- alias for X30

# Available groups
# 64-bit GPRs: X0..X28 X29(FP) X30(LR) XZR SP PC
# 32-bit views: W0..W28 W29 W30 WZR WSP
# NEON/FP (same 128-bit slot, narrower views): V0..V31/Q0..Q31 (128-bit),
#   D0..D31 (64-bit), S0..S31 (32-bit), H0..H31 (16-bit), B0..B31 (8-bit)
# NZCV flags (8-bit): NF ZF CF VF
```

---

## Backward slicer

`BackwardSlicer` propagates a register value backward through an IGNIL CFG.
Both the slicer and every `SliceExpr` it returns are context managers (owned
handles that must be destroyed).

```python
dis   = dragon.Disassembler(dragon.Architecture.X86_64)
code  = bytes([0x48, 0x39, 0xD8, 0xC3])   # cmp rax, rbx; ret
graph = dis.analyze(code, 0x5000)

with dragon.BackwardSlicer(max_blocks=5) as slicer:
    with slicer.slice_reg(graph, 0x5000, *dragon.x86.ZF) as expr:
        print(expr.to_string())
        # EQ(SUB(RAX:i64, RBX:i64), 0x0:i64)
```

Complete XMM state uses two descriptors per register: `dragon.x86.XMM0` is
its low 64 bits and `dragon.x86.XMM0_HI` its high 64 bits (likewise through
XMM15). Their offsets are `143 + 8*i` and `288 + 8*i`, not adjacent halves.
For example, symbolize both with `ex.symbolize_register(dragon.x86.XMM0,
"xmm0_lo")` and `ex.symbolize_register(dragon.x86.XMM0_HI, "xmm0_hi")`.
The symbolic executor leaves unsupplied entry XMM bytes symbolic; it does not
import host SIMD state. `dragon.x86.REGISTER_FILE_BYTES` is 416 for callers
allocating a raw register buffer for LLVM-lifted functions.

The same call works unchanged for AArch64 — swap the architecture and the
register namespace:

```python
dis   = dragon.Disassembler(dragon.Architecture.ARM64)
code  = bytes([0x1f, 0x14, 0x00, 0x71, 0xc0, 0x03, 0x5f, 0xd6])  # cmp w0, #5 ; ret
graph = dis.analyze(code, 0x5000)

with dragon.BackwardSlicer(max_blocks=5) as slicer:
    with slicer.slice_reg(graph, 0x5000, *dragon.arm.ZF) as expr:
        print(expr.to_string())
        # EQ(SUB(W0:i32, 0x5:i32), 0x0:i32)
```

### Walking the tree

```python
def print_expr(expr, indent=0):
    pad = '  ' * indent
    t = expr.type
    if t == dragon.SliceExprType.CONST:
        print(f"{pad}Const 0x{expr.const_value:x}:i{expr.const_width}")
    elif t == dragon.SliceExprType.SYM_REG:
        print(f"{pad}Reg {expr.symreg_name}:i{expr.symreg_width}")
    elif t == dragon.SliceExprType.BINOP:
        print(f"{pad}{expr.opcode_name}")
        with expr.left()  as l: print_expr(l,  indent + 1)
        with expr.right() as r: print_expr(r, indent + 1)
    elif t == dragon.SliceExprType.UNARYOP:
        print(f"{pad}{expr.opcode_name}")
        with expr.operand() as o: print_expr(o, indent + 1)
    elif t == dragon.SliceExprType.LOAD:
        print(f"{pad}Load:i{expr.load_width}")
        with expr.load_addr() as a: print_expr(a, indent + 1)
    else:
        print(f"{pad}undef")

with dragon.BackwardSlicer() as slicer:
    with slicer.slice_reg(graph, 0x5000, *dragon.x86.ZF) as expr:
        print_expr(expr)
# EQ
#   SUB
#     Reg RAX:i64
#     Reg RBX:i64
#   Const 0x0:i64
```

### SliceExpr properties

| Property / method | Type | Available on |
|---|---|---|
| `type` | `SliceExprType` | all |
| `to_string()` | `str` | all |
| `const_value` | `int` | CONST |
| `const_width` | `int` | CONST |
| `symreg_offset` | `int` | SYM_REG |
| `symreg_width` | `int` | SYM_REG |
| `symreg_name` | `str` | SYM_REG |
| `opcode` | `int` | BINOP / UNARYOP |
| `opcode_name` | `str` | BINOP / UNARYOP |
| `left()` | owned `SliceExpr` | BINOP |
| `right()` | owned `SliceExpr` | BINOP |
| `operand()` | owned `SliceExpr` | UNARYOP |
| `load_addr()` | owned `SliceExpr` | LOAD |
| `load_width` | `int` | LOAD |

### Z3 string representation

Available when dragon was built with `-DDRAGON_USE_Z3=ON`.
Raises `RuntimeError` if Z3 support is not present.

```python
z3_str = expr.to_z3_string()
print(z3_str)   # (bvadd rax #x0000000000000004)
```

The returned string is the Z3 bitvector expression in SMT-LIB2 format —
identical to what you would get from lowering with `SliceExprZ3` in C++.

### Value enumeration and unique-value solving

Also requires `-DDRAGON_USE_Z3=ON`; both raise `RuntimeError` otherwise.
Each call constructs its own Z3 context internally — there is no way to pass
extra Z3 assertions across the C boundary, unlike the C++ API's optional
`constraints` parameter; use the C++ API directly
(`dragon::slice::enumeratedValues` / `solveUnique`) if you need that.

```python
values = expr.enumerate_values()          # max_values=0 -> default cap (256), sorted=True
print(values)                             # e.g. [1, 2, 3, 5, 8]

unique = expr.solve_unique()
print(unique)                             # a single int, or None if not uniquely determined
```

| Method | Returns | Notes |
|---|---|---|
| `enumerate_values(max_values=0, sorted=True)` | `list[int]` | `max_values=0` selects the library default (256) |
| `solve_unique()` | `int` or `None` | `None` when zero or more than one model exists |

---

## SwitchDetector

Recognizes a jump-table indirect-branch pattern from a backward-slice
result (typically the target of an indirect jump, sliced with
`BackwardSlicer` above) and reads the concrete targets out of the table's
raw bytes.

```python
with dragon.BackwardSlicer() as slicer:
    with slicer.slice_reg(graph, block_addr, *dragon.x86.RAX) as jump_target:
        sw = dragon.detect_possible_switch(jump_target, block_addr, graph)
        if sw is not None:
            print(sw)   # <SwitchCandidate table_base=0x... entry_size=8 num_cases=4>

            # `rodata`/`rodata_base` describe a window of the binary's image
            # (e.g. the whole .rodata section) that contains the table.
            targets = dragon.read_table_targets(sw, rodata, rodata_base)
            for i, t in enumerate(targets):
                print(f"case {i} -> 0x{t:x}")
```

`SwitchCandidate` is a plain data object (`table_base`, `entry_size`,
`num_cases`, `index_reg_offset`, `index_reg_width` — the last two use the
same register-address-space convention as `BackwardSlicer.slice_reg()`),
returned by `detect_possible_switch()` and also constructible directly if
you already know the table's shape from other analysis.

| Function | Returns | Notes |
|---|---|---|
| `detect_possible_switch(jump_target, block_addr, graph)` | `SwitchCandidate` or `None` | A returned candidate with `num_cases == 0` means the pattern matched but the bounds guard wasn't found |
| `read_table_targets(candidate, data, base_addr)` | `list[int]` | Empty if `num_cases == 0` or the table falls outside `data` |

Not every indirect jump is a jump table — GCC and Clang often lower a
`switch` to a plain compare chain instead (no jump table at all) when the
case count is small or the cases aren't dense, in which case
`detect_possible_switch` correctly returns `None` and there's nothing
further to recover here.

---

## LLVMLifter

`LLVMLifter` lifts a `Function` to LLVM IR using the IGNIL graph.
`graph` must come from `Disassembler.analyze()` — IGNIL blocks must be present.

```python
dis   = dragon.Disassembler(dragon.Architecture.X86_64)
code  = bytes([
    0x55,                    # push rbp
    0x48, 0x89, 0xE5,        # mov  rbp, rsp
    0x48, 0x01, 0xD8,        # add  rax, rbx
    0x5D,                    # pop  rbp
    0xC3,                    # ret
])
graph = dis.analyze(code, base_address=0x1000)

lifter = dragon.LLVMLifter(arch=dragon.Architecture.X86_64, module_name='my_module')

fn = graph.get_function(0x1000)
if lifter.lift(fn, graph):
    print(lifter.ir())    # raw IR

    lifter.optimize()     # mem2reg → instcombine → GVN → DCE

    print(lifter.ir())    # optimized IR
```

### Optimization passes

Individual passes can be called separately or use `optimize()` for the
recommended pipeline.

```python
lifter.run_mem2reg()      # promotes allocas to SSA values
lifter.run_inst_combine() # folds sub-register mask/OR patterns
lifter.run_gvn()          # eliminates redundant loads
lifter.run_dce()          # removes dead flag computations

# equivalent shorthand:
lifter.optimize()
```

### Method reference

| Method | Returns | Notes |
|---|---|---|
| `lift(function, graph)` | `bool` | `False` if any IGNIL block is missing |
| `ir()` | `str` | Textual LLVM IR for all lifted functions |
| `run_mem2reg()` | — | |
| `run_inst_combine()` | — | |
| `run_gvn()` | — | |
| `run_dce()` | — | |
| `load_ir(text)` | `bool` | Import verified textual LLVM IR; failure preserves old module |
| `run_loop_reroll()` | `int` | Number of reconstructed fixed-count scalar loops |
| `verify()` | `True` | In-process LLVM structural check; raises `ValueError` on invalid IR |
| `run_pass_pipeline(pipeline)` | `True` | LLVM PassBuilder syntax; verified clone committed on success, `ValueError` on failure |
| `optimize(pipeline=None)` | `True` | Legacy four-pass sequence by default; explicit `default<O2>` selects full O2 |
| `llvm_version` | `str` | LLVM linked into libdragon, independently of the system `opt` |

Optimization and structural verification run **in process** in libdragon:

```python
with dragon.LLVMLifter() as llvm:
    if not llvm.load_ir(raw_ir):
        raise ValueError("invalid LLVM IR")
    llvm.optimize('default<O2>')
    llvm.verify()
    print(llvm.llvm_version)
    optimized_ir = llvm.ir()
```

The explicit `dragon-scalar-o2` pipeline builds O2 with SLP and loop
vectorization disabled for compact scalar projection output. `default<O2>`
remains unchanged. `function(dragon-clean-words,instcombine,dce)` reconstructs
sign extensions and removes redundant zero-count selects around same-input
funnel rotations, based on actual IR operands and widths, not sample names.
These are transformations, not replacements for an independent semantic proof.

`run_pass_pipeline('function(instcombine,early-cse,dce)')` selects a smaller
pipeline when a consumer needs to preserve a particular loop CFG. Empty/NUL or
invalid pipeline text is rejected. Passes run on a clone; parsing or structural
verification failure keeps the prior module. These APIs do **not** prove
semantic equivalence, native coverage or termination. Pipeline names are LLVM
version dependent, and this is not a resource sandbox for arbitrary passes.
No external `opt` executable is required by these APIs. `optimize()` with no
argument still means the legacy mem2reg/InstCombine/GVN/DCE sequence, not O2.


The library also registers these pipeline names:

- `function(dragon-coalesce-add-reductions)` quotients independent same-width
  wrapping ADD recurrences by their sum, only when every observation uses all
  selected accumulators once. Currently limited to two-block, single-latch
  loops. Per-lane observations, feedback and flagged updates are not guessed.
  PHI `!dragon.reduction` metadata proposes original coordinates; it is not a
  proof. Callers must independently verify seeds, parallel next state, guard
  and observations with the proposed many-to-one mapping.
- `function(dragon-fold-small-selects)` folds EQ/NE and signed-comparison
  select DAGs over one selector into integer-valued polynomials. i1..i4 domains
  are exhaustive; wider selectors use actual dominating CFG edges and decision
  cuts to enumerate at most 16 consecutive representatives, with constant tails
  represented by signed clamps. No captured input or ordinary predecessor edge
  is treated as a reachability proof.
  Exact rational power-basis factoring and common-factor extraction compete
  with the Newton/falling-product form by emitted instruction count. Small
  rational roots are only proposals validated by exact synthetic division.
  Absolute coefficient bounds protect numerators before division; payloads keep
  their original modular width. Selector and opaque operands are frozen once.
  Only degree-at-most-4, strictly smaller rewrites are committed; unsupported
  DAGs stay intact. No source-algorithm or sample-specific templates are used.
- `function(dragon-normalize-modular-polynomials)` performs bounded exact
  integer-ring normalization with shared-factor/Horner construction, committing
  only smaller actual arithmetic DAGs. Unflagged constant SHL is exact modular
  scaling; overshifts and nonredundant nowrap flags remain opaque.
  KnownBits may justify constant bitwise-to-arithmetic conversion and redundant
  ADD flags. Width-changing operations, select, memory and freeze remain
  opaque. Limits: 64 monomials, degree 4, depth 64 and 65,536 work units per
  function; exhaustion leaves the remaining expressions unchanged.

- `function(dragon-coalesce-affine-ivs)` removes one redundant integer PHI per
  natural loop when ScalarEvolution proves two affine IVs differ by a constant.
  It does not infer a source loop, a trip count or a termination promise.
- `function(dragon-clean-ir-names)` gives blocks/loop PHIs neutral names and
  removes only `dragon.*` instruction metadata. No instructions or CFG edges
  are removed; retain the preceding metadata-bearing artifact for state proofs.

`dragon-propose-scalar-loops` is a **module** pass that adds separate
`<original>.dragon.scalar.N` hypotheses and retains the original function.
For a two-block loop with two same-width integer PHIs, constant nonnegative IV
seed, constant accumulator seed and stride 2..16, it inverts a degree-at-most-3
integer polynomial batch increment into a unit-step recurrence. The limits are
8..64-bit state and bounded 256-bit coefficient work; unsupported operations,
nonredundant nowrap flags or non-integral inversion leave the original intact.
Proposed limits come from actual arguments or low-width argument truncations.
**Polynomial inversion is not a proof of entry/exit equivalence. Do not select a
hypothesis based only on LLVM verification.**

The generic Python exporter independently proves an inductive interval/congruence,
entry alternatives, exact stride-step correspondence and bounded real exit tails
against the canonical CFG. Only a proved candidate with fewer SSA definitions is
selected; otherwise the preceding proved output is retained. This recovers a
parameter-controlled scalar loop rather than a fixed capture trip count. It may
increase runtime iteration count by the batch stride: the selection objective is
readable IR, not a claim of faster generated code.

For recovered scalar loops, run InstCombine before coalescing packed PHIs,
then small-select folding, polynomial normalization and scalar cleanup. These transformations do not
perform loop discovery, recover omitted entry paths or establish native-code
coverage. After the canonical CFG is independently proved, LICM/rotation/IV
cleanup and name cleanup can produce a more readable CFG. The generic Python
exporter separately proves entry, affine cutpoint correspondence, parallel step,
branches, returns and definedness against the canonical CFG, retaining the
canonical output if that check is unsupported or fails. LLVM verification alone
does not establish semantic equivalence.

For compact post-O2 IR:

```python
with dragon.LLVMLifter() as llvm:
    if not llvm.load_ir(optimized_ir):
        raise ValueError("invalid LLVM IR")
    loops = llvm.run_loop_reroll()
    compact_ir = llvm.ir()
```

This matches repeated closed scalar integer recurrences, not sample names or
known algorithms. Operation semantics, flags, constants and operand structure
must match exactly; memory/calls, freeze, FP, vectors and external intermediate
uses are excluded. It is fixed-count rerolling, not parameter-bound loop
recovery. Independently verify the output before using it.

---

## FLIRT signatures

`SignatureDB` loads FLIRT-style `.pat` signature databases and matches them
against disassembled bytes. Text `.pat` format only (the proprietary binary
`.sig` format is not supported).

`dragon.sigs_crc16(data)` exposes the raw CRC16 primitive used to verify
matches (reflected, poly `0xA001`, init `0xFFFF`, no final XOR — CRC-16/ARC)
standalone — useful for checking it against a real `.pat` file, since it was
only ever verified self-consistently against this codebase's own parser.

```python
db = dragon.SignatureDB()
db.load_directory('./signatures')   # every .pat file in the dir, non-recursive
print(db.signature_count)

# Single candidate: try every signature against code starting at 0x1000.
match = db.match_at(code, 0x1000)
if match:
    address, name, length = match
    print(f'{name} at 0x{address:x}, length {length}')

# Many candidates at once: every entry point against every signature.
# A module can bundle more than one function/offset under one pattern, so
# one entry point may produce more than one match in the result list.
for address, name, length in db.match_entries(image, image_base, [0x1000, 0x1040]):
    print(f'0x{address:x}: {name} (len {length})')
```

### Method reference

| Method | Returns | Notes |
|---|---|---|
| `SignatureDB()` | | |
| `load_directory(path)` | — | Every `.pat` file directly inside `path`, not recursive; unparseable files are silently skipped |
| `load_file(path)` | — | No-op if the file can't be parsed |
| `signature_count` | `int` | |
| `match_at(data, address)` | `(address, name, length)` or `None` | `data` must begin at the candidate function's address |
| `match_entries(image, image_base, entry_points)` | `list[(address, name, length)]` | |
| `dragon.sigs_crc16(data)` | `int` | Module-level function, not a `SignatureDB` method |

---

## Symbolic execution

Available when the library is built with `-DDRAGON_USE_Z3=ON`.

`SymbolicExecutor` runs lifted IGNIL over Z3 bitvectors: seed the machine, run
a block, then ask the solver what it computed. Registers are the
`(offset, width, name)` tuples from the `x86` / `arm` classes.

```python
import dragon
from dragon import x86

cfg = dragon.Configuration(strategy=dragon.Strategy.LINEAR_SWEEP)
dis = dragon.Disassembler(dragon.Architecture.X86_64, cfg)

#   xor rax, rdi ; add rax, rsi ; ret
graph = dis.analyze(bytes([0x48,0x31,0xF8, 0x48,0x01,0xF0, 0xC3]), 0x1000)
block = graph.get_ignil_block(0x1000)

with dragon.SymbolicExecutor() as ex:
    ex.set_register(x86.RAX, 0)
    a = ex.symbolize_register(x86.RDI, 'a')
    b = ex.symbolize_register(x86.RSI, 'b')

    result = ex.run(block)

    rax = ex.read_register(x86.RAX)
    print(ex.proves(rax == a + b))   # True
    print(ex.proves(rax == a * b))   # False
```

State persists across `run()` calls, so walking a path is a sequence of runs.

### Expressions

`SymExpr` operators build expressions rather than computing anything, so `==`
returns a `SymExpr` and not a `bool` — the same convention z3py uses. Plain
ints are widened to the other operand's width automatically.

```python
rax = ex.read_register(x86.RAX)

goal   = rax == 0x1337          # SymExpr, not a bool
masked = (rax & 0xFF) + 1
```

Comparison operators (`<`, `<=`, `>`, `>=`) are **signed**, matching Python's
own integer semantics. Use `ult()`, `ule()`, `ugt()`, `uge()` for the unsigned
versions, `logical_and()` / `logical_or()` / `implies()` to combine booleans,
and `~` for boolean negation.

> Expressions may safely outlive the executor that produced them. A
> `z3::expr` does not own its context, so each handle keeps the executor
> alive itself — which is what makes `SymExpr` objects safe to hold in
> globals, where Python finalizes in an order you do not control.

### Solving — recovering an input

A symbolic region of N bytes creates N variables named
`<region>[0]`..`<region>[N-1]`, which `Solution.bytes()` reads back in address
order.

```python
#   mov rax, [rdi] ; xor rax, rsi ; ret
with dragon.SymbolicExecutor() as ex:
    ex.set_register(x86.RDI, 0x4000)
    ex.set_register(x86.RSI, 0x5A5A5A5A5A5A5A5A)
    ex.symbolize_memory(0x4000, 8, 'flag')
    ex.run(block)

    solution = ex.solve(ex.read_register(x86.RAX) == ex.const(target, 64))
    if solution:
        print(solution.bytes('flag'))    # b'DRAGON!!'
        print(solution.values())         # every bound symbol
```

`solve()` returns `None` when no assignment exists — an unreachable goal is
reported, never guessed at. Narrow the search with `assume()` before running:

```python
for i in range(4):
    byte = ex.read_memory(0x5000 + i, 8)
    ex.assume(byte.uge(ex.const(0x21, 8)))    # printable ASCII only
    ex.assume(byte.ule(ex.const(0x7E, 8)))
```

### Control flow — resolving computed jumps

`RunResult.successors` names the concrete addresses control flow can reach,
each with the guard under which it is reached. A branch whose condition is
provably constant collapses to a single successor; a computed jump has its
target enumerated, which is what recovers a jump table or a VM dispatch.

```python
#   mov esi, [rdi] ; jmp qword ptr [rsi*8 + 0x6000]
with dragon.SymbolicExecutor() as ex:
    ex.map_memory(0x6000, handler_table)
    ex.set_register(x86.RDI, 0x7000)

    opcode = ex.symbolize_memory(0x7000, 4, 'vm_opcode')
    ex.assume(opcode.ult(ex.const(3, 32)))     # the VM's own range check

    result = ex.run(block)
    print(result.complete)                     # True
    print([hex(s.address) for s in result.successors])
    # ['0xaa00', '0xbb00', '0xcc00']
```

`result.complete` is the honesty check: True only when the run succeeded *and*
every address and branch target resolved exactly, so the successor list really
is the complete set. Otherwise `result.warnings` says what had to be left open:

```python
for w in result.warnings:
    print(f"@0x{w.address:x}: {w.message}")
# @0x1002: branch target has more than 256 possible values ...
```

### Modelling notes

- Registers and memory are byte-granular, so sub-register aliasing comes out
  right: `EAX` writes bytes 0–3, `AH` writes byte 1, and a `RAX` read
  concatenates bytes 0–7.
- A 32-bit write clears the upper half of a 64-bit register (x86-64 and
  AArch64). Pass `zero_extend_on_32bit_write=False` for a target where it
  merges instead.
- A symbolic address is concretized by enumerating its satisfying values, up
  to `max_address_solutions`; past that bound the access is reported
  unresolved rather than guessed at.
- Blocks stop at the first terminator. Pass `stop_at_terminator=False` to run
  a trace from `lift_trace()`, whose interior terminators must be stepped
  over.

### Concrete readback and OPAQUE ops

`concrete_register(reg)` and `concrete_memory(address, width)` return a plain
`int` when the location holds a literal, or `None` when it is still symbolic —
the cheap form of `evaluate(read_register(reg))` for a value expected to be
concrete, with no expression handle and no solver. `write_register(reg, expr)`
and `write_memory(address, expr)` store an expression rather than a host
integer (`write_memory` is little-endian, as wide as the expression).

An OPAQUE op — `CPUID`, `RDTSC`, `RDTSCP` — has a value IGNIL cannot express
directly. **The symbolic executor now defaults to native analysis-host
RDTSC/RDTSCP sampling.** CPUID remains an uninterpreted function unless pinned
explicitly; host CPU feature probing for the timing helper does not substitute
host CPUID results into the target state. Pin a target CPUID observation with:

```python
# CPUID(leaf=1, sub=0) -> fixed EAX/EBX/ECX/EDX
ex.set_concrete_cpuid(1, 0, 0x000906EA, 0, 0x7FFAFBFF, 0xBFEBFBFF)
```

`set_concrete_opaque(kind, selector, results)` is the general form for the
other kinds (`OPAQUE_CPUID`, `OPAQUE_RDTSC`, `OPAQUE_RDTSCP`), where `selector`
identifies the invocation from its operands.

### Native timestamp default

```python
ex = dragon.SymbolicExecutor()                 # host timing, library default
ex = dragon.SymbolicExecutor(host_timestamps=False)  # explicit symbolic timing
ex.set_host_timestamps(True)                   # does not alter GPR/memory state
print(ex.host_timestamps)
result = ex.run(block)
for event in result.timing_events:
    print(event['address'], event['kind'], event['tsc'], event['aux'])
```

Each dynamic timestamp instruction reads once in the C++ executor. EAX/EDX
(and RDTSCP's ECX/TSC_AUX) come from that same observation. Samples are not cached
by static PC or stored in state snapshots; a repeated execution samples again.
`timing_events` reports address, kind, complete TSC, EAX, EDX, AUX and source.
Explicit `set_concrete_opaque` registrations take precedence. Unsupported host
instructions stay symbolic with a warning, not a fabricated zero/wall-clock.

These are **analysis-host observations**, not originating-machine time replay
or target-speed timing. A proof/path computed with them is conditional on those
samples and other fixed environment state, not universal over all time values.
Disabling host timestamps retains the prior symbolic timing model. All input
register/memory symbolization policies are unchanged.

### Snapshots and diffing

Copying state is far cheaper than rebuilding it, so an analysis that runs many
blocks from one seeded machine should seed once and rewind. `snapshot()`
returns a `SymState`, and `restore()` puts it back:

```python
with dragon.SymbolicExecutor() as ex:
    ex.symbolize_memory(0x4000, 16, 'input')
    ex.set_register(x86.RDI, 0x4000)
    seeded = ex.snapshot()

    for block in blocks:
        ex.restore(seeded)
        ex.run(block)
        ...
```

`diff(before)` reports every register and memory location whose value differs
from a snapshot, as a list of `StateDelta` (`kind` is `'reg'` or `'mem'`, `key`
the register offset or address, `width` in bits, `value` the `SymExpr` now
held). A run of bytes that came from one written value is reported as that
single value, so a 64-bit store is one delta and not eight.

```python
seeded = ex.snapshot()
ex.run(block)
for d in ex.diff(seeded):
    print(d.kind, hex(d.key), d.width, d.value)
```

`SymState.merge(incoming, tag)` joins another snapshot into this one, turning
every location the two disagree on into a fresh variable named after `tag`, and
returns the symbolised locations as a `StateDelta` list — an empty list is the
fixed-point signal for a worklist exploration. `set_fresh_tag(tag)` sets the
suffix for the variables `run()` invents for loads it cannot resolve, so the
same block run in two contexts can keep its fresh names apart.

`SymState.join_guarded(incoming, condition)` is the **exact**, non-widening
boundary join: select incoming physical registers/memory when condition is true,
this snapshot otherwise. Guarded constraint suffixes are retained rather than
conjoined across mutually exclusive paths. Concrete images must be shared; array
memory effects and active access observers are excluded. Use only between complete
native blocks: block-local temporaries are discarded. The returned Boolean SymExpr
is a projection violation to check independently for UNSAT, not an assumption.
This API does not establish coverage/disjointness or applicability at another call;
the exploration layer must prove those separately.

### Unresolved accesses

When a symbolic address has more satisfying values than
`max_address_solutions`, the access cannot be expanded: the load produces a
fresh variable and the store is dropped, each with a warning.
`RunResult.unresolved` lists them as `UnresolvedAccess` objects (`is_store`,
`op_address`, `width`, `address`, `value`).

### Exporting an expression

Besides `to_string()`, a `SymExpr` can leave the library:

```python
print(expr.as_int())      # int if it folds to a <=64-bit literal, else None
print(expr.to_smt2())     # a complete SMT-LIB 2 script, declarations included
z3_term = expr.to_z3()    # a z3py term (needs the z3-solver package)
```

`to_smt2()` emits a self-contained script another Z3 binding can parse back
without being told the free variables; `to_z3()` does exactly that and hands
back the term.

### API summary

| Symbol | Description |
|---|---|
| `SymbolicExecutor(**options)` | Create an executor (see options below) |
| `set_register(reg, value)` | Seed a register concretely |
| `symbolize_register(reg, name)` → `SymExpr` | Bind a register to a fresh variable |
| `map_memory(addr, data)` | Map a concrete blob |
| `symbolize_memory(addr, size, name)` → `SymExpr` | Fill a region with per-byte variables |
| `assume(cond)` | Constrain the rest of the run |
| `run(block)` → `RunResult` | Execute a block; state persists |
| `read_register(reg)` / `read_memory(addr, width)` → `SymExpr` | What a location now holds |
| `const(value, width)` → `SymExpr` | A concrete bitvector |
| `proves(cond)` → `bool \| None` | Does it hold on every model? `None` = solver gave up |
| `is_satisfiable(cond)` → `bool \| None` | Can it hold at all? |
| `evaluate(expr)` → `int \| None` | Value, only if it is forced to exactly one |
| `enumerate(expr, max)` → `(list, bool)` | Distinct values, and whether that list is complete |
| `solve(goal)` → `Solution \| None` | A satisfying assignment |
| `write_register(reg, expr)` / `write_memory(addr, expr)` | Store an expression, not a host int |
| `concrete_register(reg)` / `concrete_memory(addr, width)` → `int \| None` | Literal value, or `None` if symbolic |
| `set_concrete_cpuid(leaf, sub, eax, ebx, ecx, edx)` | Pin a CPUID OPAQUE result |
| `set_concrete_opaque(kind, selector, results)` | Pin any OPAQUE result, ahead of host timing |
| `host_timestamps` / `set_host_timestamps(enabled)` | Query/toggle native timing (default on) |
| `RunResult.timing_events` | Paired dynamic analysis-host timestamp observations |
| `set_fresh_tag(tag)` | Suffix for auto-invented load variables |
| `snapshot()` → `SymState` / `restore(state)` | Copy / rewind the whole machine state |
| `diff(before)` → `list[StateDelta]` | Locations changed since a snapshot |
| `reset()` | Clear register, memory and constraint state |
| `RunResult.successors` | `Successor(address, taken, condition)` list |
| `RunResult.complete` | True only if that list is exhaustive |
| `RunResult.warnings` | `SymWarning(address, message)` list |
| `RunResult.unresolved` | `UnresolvedAccess(is_store, op_address, width, address, value)` list |
| `RunResult.ops_executed` / `.solver_queries` / `.addresses_concretized` | Run statistics |
| `Solution.value(name)` / `.values()` / `.bytes(region)` | Read the model back |
| `SymState.merge(incoming, tag)` → `list[StateDelta]` | Join another snapshot; `[]` is the fixed point |
| `SymExpr.as_int()` / `.to_smt2()` / `.to_z3()` | Fold to a literal / SMT-LIB 2 / z3py term |

Constructor options, all deferring to the library default when omitted:
`solver_timeout_ms` (5000), `max_address_solutions` (64),
`max_branch_targets` (256), `zero_extend_on_32bit_write` (True),
`symbolize_unmapped_reads` (True), `stop_at_terminator` (True).

`examples/python/symbolic_execution.py` runs all of the above against real
lifted x86-64.

---

## Enum reference

| Class | Values |
|-------|--------|
| `dragon.Architecture` | `UNKNOWN`, `X86_32`, `X86_64`, `ARM32`, `ARM64`, `RISCV32`, `RISCV64` |
| `dragon.Syntax` | `INTEL`, `ATT` |
| `dragon.Strategy` | `LINEAR_SWEEP`, `RECURSIVE_TRAVERSAL` |
| `dragon.SliceExprType` | `CONST`, `SYM_REG`, `BINOP`, `UNARYOP`, `LOAD`, `UNDEF` |
| `dragon.IGNILOpcode` | `COPY`, `LOAD`, `STORE`, `ADD`, … `UNDEF`, `FADD`, `FSUB`, `FMUL`, `FDIV`, `SITOFP`, `FPTOSI`, `OPAQUE` (43 values) |
| `dragon.Format` | `UNKNOWN`, `ELF`, `PE` |
| `dragon.SymbolKind` | `UNKNOWN`, `FUNCTION`, `OBJECT`, `SECTION`, `FILE` |
| `dragon.SymExecStatus` | `OK`, `MALFORMED_OP`, `UNSUPPORTED_OP`, `SOLVER_FAILURE` |
| `dragon.SymExit` | `FALLTHROUGH`, `JUMP`, `CONDITIONAL_JUMP`, `CALL`, `RETURN`, `ERROR` |
| `dragon.SwitchCandidate` | `table_base`, `entry_size`, `num_cases`, `index_reg_offset`, `index_reg_width` (plain data, not an enum) |
| `dragon.SimplifyStats` | `constants_folded`, `identities_applied`, `ops_removed`, `iterations`, `changed` (plain data, not an enum) |
| `dragon.Section` | `name`, `address`, `virtual_size`, `readable`, `writable`, `executable`, `data` (plain data, not an enum) |
| `dragon.Symbol` | `name`, `address`, `size`, `kind`, `imported`, `exported` (plain data, not an enum) |
| `dragon.StateDelta` | `kind`, `key`, `width`, `value`, `is_register` (plain data, not an enum) |

### Resolved symbolic paths

`LLVMLifter.lift_path(steps, name='resolved_path')` exports a finite x86-64 path
using existing IGNIL operation lowering. Each step has `body` (IGNILBlock or
None), `address`, `next_address`, `transfer` (`next`, `call`, `return`), optional
`return_address` for CALL and `stack_adjustment` for RET-immediate. Bodies are
borrowed during the call; repeated source addresses are separate contexts.
The final step must return. Bodies must not include CALL/RET themselves, and a
JMP/CJMP, if present, must be the last operation in a `next` step.

```python
with dragon.LLVMLifter() as llvm:
    if not llvm.lift_path(steps, name='recovered_path'):
        raise ValueError('invalid resolved path')
    raw = llvm.ir()
    llvm.optimize()  # existing mem2reg -> InstCombine -> GVN -> DCE
    optimized = llvm.ir()
```

CALL/RET stack effects are modeled; intermediate returns continue in the same
LLVM function. Branch/return targets are guarded with `llvm.assume`. The result
retains `(mem, regs)` and requires the path's preconditions. It is not all-path
CFG recovery, does not embed capture memory/opaque observations and does not
assert native equivalence. `SymbolicExecutor` host timestamp policy does not
supply implementations for the external opaque declarations in LLVM IR.

### Typed semantic expressions and memory-effect functions (Z3 build)

`LLVMLifter.lift_expression(expression, arguments, name='recovered')` lowers an
actual recovered Bool/BitVec DAG to a typed **pure return-only** function. It
rejects undeclared symbols, unsupported operations, mixed contexts and duplicate
inputs. SMT shifts remain defined even when the shift amount exceeds the width;
no model-selected constants or algorithm templates are inserted.

Total integer BV division/remainder is supported, including zero divisors and
signed MIN/-1. The LLVM divisor is guarded before executing div/rem (a select
of an invalid result alone would not prevent UB). Signed modulo is distinct
from signed remainder; i1 uses a division-free truth table. Expression-function
arguments carry `noundef`: arbitrary concrete BV words do not include LLVM
undef/poison, and this adds no numeric input restriction. The independent
workspace checker still verifies definedness and equality to the original DAG.
`dragon-clean-words` also restores whole-word constant-count funnel operands
when their observed low bits agree, enabling CSE/rotate cleanup before O2.

For pointer/in-out functions use `SymbolicExecutor.enable_memory_effects()`
**before** executing a resolved path, followed by `LLVMLifter.lift_effects`:

```python
executor = dragon.SymbolicExecutor()
p = executor.symbolize_register(dragon.x86.RCX, 'p')
q = executor.symbolize_register(dragon.x86.RDX, 'q')
x = executor.symbolize_register(dragon.x86.R8D, 'x')
executor.enable_memory_effects()
# Run validated IGNIL blocks for the function's resolved path here. Keep their
# Graph owners alive while constructing/using borrowed native instructions.
result = executor.run(body)
assert result.complete and not result.unresolved
with dragon.LLVMLifter() as llvm:
    assert llvm.lift_effects(executor, executor.read_register(dragon.x86.EAX),
                             [p, q, x], pointers=[0, 1], name='recovered')
    llvm.optimize()
    print(llvm.ir())
# For a void function pass expression=None instead.
```

- `pointers` contains **argument indices** whose BV64 source symbols become LLVM
  `ptr` parameters. No `noalias`, independent-object or `inbounds` assumption is
  introduced; accesses have alignment 1. Pointer-to-pointer runtime loads work.
- Every executed IGNIL LOAD/STORE uses the **same** BV64-to-BV8 array, little
  endian. Stores update one byte at a time; loads are fresh runtime tokens tied
  to the array version at that exact point. Equal pointers, partial overlaps,
  read-after-write and stores absent from the return DAG are preserved.
- `executor.memory_effects`: ordered dictionaries with `is_store`, `address_pc`,
  `width`, `address`, `value`. Load values are result tokens, not captured data.
- `executor.effect_memory(initial=False)`: final or initial array as `SymExpr`;
  `.to_z3()` supports arrays. `effect_constraints()` returns load equalities.
- This mode is opt-in **all-memory**. The initial array is unconstrained; existing
  `map_memory`/`read_memory`/`write_memory` capture storage is separate, and is not
  imported. Stack/image/environment accesses are not automatically hidden or
  specialized; consumers must explicitly supply all remaining dependencies.
- Snapshot/restore copies array versions and ordered events. Reset disables this
  mode. Concrete `diff` and widening `merge` reject effect states instead of
  silently losing symbolic-address stores. Fresh load tokens stay distinct after
  restoring a snapshot. Unlifted instructions or failed/warned runs invalidate
  effect export; raw-op callers must independently retain source coverage.
- Finite resolved paths, ordinary valid memory only. Caller verifies ABI,
  control-flow completeness and path/environment preconditions. This does not
  model volatile/MMIO, atomics, concurrent observations, memory faults or all-path
  CFG behavior, and is not an automatic pointer-aware capture driver.

`add/llvm_export.py::export_effects` saves raw, library-optimized and O2 IR, runs
LLVM verification, and independently parses emitted IR to prove **both return
and entire final byte-array equality** against symbolic source semantics. The
checker fails on unsupported IR or inconsistent load constraints. See
`add/test_llvm_effects.py` for alias/overlap/order and generated-fixture tests.

### Physical liveness and recovered loop regions

`executor.begin_access_trace(ranges)` watches `(kind, byte_offset, byte_count)`
triples (`kind='reg'` or `'mem'`); `[]` watches all accessed bytes.
`end_access_trace()` disables the observer in all snapshots sharing it and
returns dictionaries containing `kind`, `key`, `live_in`, `read`, `written`.
`live_in` means read before the first physical write, including overlapping
aliases and the high-half clearing of an architectural 32-bit GPR write.
Tracking is bounded to 1,048,576 distinct bytes; overflow raises rather than
silently accepting incomplete liveness. Tracing is opt-in and off by default.

`executor.symbolize_range(kind, key, width, name)` binds an analysis-time
physical byte range to a free bitvector, without the architectural zero-clear
side effect of `symbolize_register(EAX, ...)`. Subsequent real EAX writes still
clear the upper 32 bits. It is not an instruction semantics override.

`executor.parse_condition(smtlib)` imports the conjunction of SMT-LIB assertions
into the executor's own Z3 context **without assuming it**. Existing symbols
are identified by matching names and sorts. `specialize_equality(condition)`
rewrites register/memory/temporary expressions only after proving `lhs == rhs`
from the retained constraints: `True` on success, `False` if not implied,
`None` on invalid input or an unknown proof. The path assumptions remain
unchanged; memory-effects recording is deliberately excluded. The caller must
preserve the applicable guard when exporting such a specialized state.

`set_concrete_opaque(kind, selector, [])` removes that override, restoring the
configured default (including host timing); it does not change CPUID policy.

`llvm.lift_loop_region(inputs, carried, next_values, continuation, name=...)`
builds a header/body/exit CFG with **simultaneous** PHI updates from recovered
symbolic DAGs. Arguments must be distinct free boolean/bitvector constants in
one context; each next value must have its carried value's sort. Its interface
is `while continuation(state, inputs): state = next_values(state, inputs)`,
returning a struct of the header state on the failed continuation. The caller
owns the invariant, reachability/termination proof, original entry branches,
and native exit projection. This API alone is not a complete-function lifter
or a proof of native-code equivalence.


An equality passed to `specialize_equality` is kept in its original binary
form until the implication has been checked. A singleton `And` wrapper is
accepted; Boolean equalities such as `predicate == true` are not simplified
away before selecting the substitution operands. This is still a proof-only
rewrite, not a way to add an unproved constraint.

Exhaustive singleton address enumeration also feeds its proved equality back
into ordinary register/memory/temporary state. Bounded selector probes may
propagate further implied equalities, but retain every original constraint;
no arbitrary model value is selected. Memory-effects recording is excluded.

### Loop-function lowering and proof-only projection simplification

`LLVMLifter.lift_loop_function(inputs, carried, initial, next_values,
continuation, returned, name='recovered_loop', *, entry_guard=None,
otherwise=None)` emits a scalar-return function with simultaneous carried PHIs.
Inputs carry `noundef`: these Z3 bit-vectors denote arbitrary concrete machine
words, not LLVM undef/poison. This is not a capture-value specialization.
Seeds depend only on inputs. Condition, updates and return may also depend on
carried state. An optional entry guard/otherwise pair emits a real outer branch,
not an assume. No affine counter, fixed trip count or termination is assumed;
zero carried values are supported. This API alone does not establish native
coverage or recover caller-visible memory effects.

`SymbolicExecutor.parse_expression(script)` imports one BV expression from
exactly one `(= |dragon!result| value)` assertion, without altering machine state
or assumptions. The marker must be a free BV constant on exactly one side and
must not occur in the value. Malformed scripts/recursive markers are rejected.

`value, stats = executor.simplify_projection(expression, domain, inputs=(),
timeout_ms=2000)` performs budgeted proof-guided pure DAG simplification in the
library. `inputs` are same-executor free BV constants. Small-slice guard
projections are accepted only after exhaustive enumeration and an UNSAT
replacement check under the explicit Boolean `domain`. Boolean roots can also be projected to proved whole-word predicates, with
threshold candidates derived from observed input slices and DAG literals.
A model-proposed constant return is accepted only after a second UNSAT query
proves uniqueness over the entire domain; it is not input sampling.
Machine path assumptions are not used; state is not changed. Stats contain
`queries` and `rewrites`.
Unproved candidates are left unchanged. The result's equivalence is restricted
to `domain`; use `true`, not the last returning path guard, for an unconditional
merged-return export. This does not infer a source algorithm or concrete inputs.

### Deterministic fixed-layout state summaries

`trace = executor.begin_call_trace()` returns an owned `CallTrace`. Snapshot the
entry before starting it; snapshots share its union observer and copy definite
writes per path. At every matched return call `trace.detach()` on the restored
executor, then gather all local returns and prove/exactly join the full states.
`trace.cacheable` reports footprint/execution eligibility, not coverage or proof.

`summary = StateSummary(executor, before, joined, trace, return_slot, tag,
rewrites=())` owns a physical-state transformer. `rewrites` are previously proved
exact result equations. Inputs include path-local entry reads and conditionally
preserved bytes; outputs include all written bytes, even if their old and new
values happened to coincide. `summary.shape` gives input/output range counts.

Independently prove `summary.projection_violation.to_z3()` UNSAT before publishing
and `summary.applicability_violation().to_z3()` UNSAT before each `summary.apply()`.
Applicability proves existential source-input coverage, preserving correlations;
it is not a solver-model substitution. Apply evaluates every new output from
pre-application inputs before writing raw physical byte ranges. There must be no
intervening state mutation. Neither method silently imports source assumptions.

The supported domain is deterministic, ordinary fixed-layout captured memory.
RSP/data addresses are not rebased. `executor.read_control_memory(addr, width)`
marks actual RET control reads; data reads remain ordinary `read_memory` calls.
Only control-only reads of this invocation's own return slot may be excluded;
writes to that slot reject caching. Opaque/undefined/unlifted/unresolved execution
invalidates candidates. In particular, a host RDTSC observation is not replayed
at a later invocation. The C++ library handles physical state; Python orchestrates
coverage, independent queries and fallback. Scalar LLVM helpers remain separate
return projections, not native ABI or arbitrary pointer-writeback interfaces.
