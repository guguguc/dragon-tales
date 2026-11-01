#pragma once

#include <dragon/Architecture.hpp>
#include <dragon/lifters/ignil/IGNIL.hpp>

#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>

#include "utils/Logger.hpp"

#include <array>
#include <functional>
#include <map>
#include <span>
#include <unordered_map>

namespace dragon {

// Forward declarations, avoid using long headers
class BasicBlock;
class Graph;
class Instruction;

namespace x86 {

/// x86 EFLAGS register identifiers, used as keys in the emitArithFlags map.
enum class X86Flag : std::uint8_t { CF, PF, AF, ZF, SF, OF, DF };

/// Accumulator sign-extension forms (no explicit operands, no flags).
enum class AccExtend : std::uint8_t { CBW, CWDE, CDQE, CWD, CDQ, CQO };
/// Single-flag instructions: STC/CLC/CMC on CF, CLD on DF.
enum class CarryOp : std::uint8_t { STC, CLC, CMC, CLD };

/// Where a rotate/shift gets its count: an explicit imm8 operand, the
/// implicit 1 of the dedicated by-1 opcode, or the CL register.
enum class ShiftCount : std::uint8_t { Imm, One, CL };
/// Which bit a BTS/BTR/BTC instruction does to the selected bit.
enum class BitOp : std::uint8_t { Set, Reset, Complement };

/// Callable that appends IGNIL ops for a single flag into a Block.
/// Receives the block and the running temp-id counter by reference.
using FlagSetter = std::function<void(ignil::Block &, std::uint32_t &)>;

/// A lifter for x86/x86_64 machine instructions to IGNIL
///
/// Construction scans the MCRegisterInfo once to build the
/// LLVM-register integer -> ignil::Reg mapping. Lifting
/// itself is then a pure integer-comparison dispatch with no
/// string work.
/// Not all the instruction set is supported.
class X86IGNILLifter {
  public:
  X86IGNILLifter(internal::Logger& logger, Architecture architecture, const llvm::MCInstrInfo &instrInfo,
                 const llvm::MCRegisterInfo &regInfo);

  /// Lift a complete basic block into an ignil::Block.
  [[nodiscard]] ignil::Block liftBlock(const BasicBlock &block,
                                       const Graph &graph) const;

  /// Lift an arbitrary linear sequence of instructions - e.g. a captured
  /// execution trace, not necessarily a single valid basic block or a
  /// coherent CFG - into one flat ignil::Block by lifting each instruction
  /// independently via the same dispatch liftBlock uses, and concatenating
  /// the results in sequence order.
  ///
  /// Unlike liftBlock, this never consults a Graph and never synthesizes a
  /// fall-through terminator: a trace's control flow is already resolved
  /// by construction (whatever branch each instruction took to reach the
  /// next one in the sequence already happened), so each instruction's own
  /// JMP/CJMP/CALL/RET op - if any - is kept exactly as decoded, targets
  /// and all, rather than second-guessed against block/function structure
  /// this input was never claimed to have.
  [[nodiscard]] ignil::Block
  liftTrace(std::span<const Instruction> trace) const;

  private:
  // How one MOVZX/MOVSX spelling extends: the width in bits of the value
  // being widened, and whether that value comes from memory (the rm forms)
  // rather than a register (the rr forms).
  struct MovExtendForm {
    ignil::Width srcWidth;
    bool memorySource;
  };

  internal::Logger& logger_;

  Architecture architecture_;
  const llvm::MCInstrInfo *instrInfo_; // used for MCInstrDesc flag checks

  /// Lift a single instruction, appending Ops to out.
  /// tempId is the next available temporary index (incremented as needed).
  void liftInstruction(const Instruction &insn, ignil::Block &out,
                       std::uint32_t &tempId) const;

  /// Dispatch for the rotate / bit-operation family added for VMProtect
  /// mutation handlers (ROL/ROR/RCL/RCR, BTS/BTR/BTC, BSF/BSR, CMOVcc, XADD,
  /// memory INC/DEC, accumulator XCHG, MOV8ri_alt, LAHF/SAHF). Returns true if
  /// it handled the opcode. Separated from liftInstruction's main else-if
  /// chain so the chain stays under MSVC's block-nesting limit (C1061).
  [[nodiscard]] bool liftExtendedForm(unsigned opc, const llvm::MCInst &mc,
                                      std::uint64_t addr, ignil::Block &out,
                                      std::uint32_t &tmp) const;

  // Per-opcode lifting helpers
  void liftMov(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
               std::uint32_t &tmp) const;
  void liftMovLoad(const llvm::MCInst &mc, std::uint64_t addr,
                   ignil::Block &out, std::uint32_t &tmp) const;
  void liftMovStore(const llvm::MCInst &mc, std::uint64_t addr,
                    ignil::Block &out, std::uint32_t &tmp) const;
  void liftAdd(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
               std::uint32_t &tmp) const;
  void liftSub(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
               std::uint32_t &tmp) const;
  // RMW memory-destination forms: op[0..4]=mem(lhs, also destination),
  // op[5]=reg-or-imm(rhs). Loads the current value, computes the result,
  // writes it back to the same address, then sets flags exactly like the
  // register form.
  void liftAddMem(const llvm::MCInst &mc, std::uint64_t addr,
                  ignil::Block &out, std::uint32_t &tmp) const;
  void liftSubMem(const llvm::MCInst &mc, std::uint64_t addr,
                  ignil::Block &out, std::uint32_t &tmp) const;
  // reg += [mem] / reg -= [mem]: op[0]=dst(out), op[1]=src1(tied=dst),
  // op[2..6]=mem(rhs). Loads rhs, then the same ADD/SUB + flags as the rr
  // form. Found by scripts/audit_x86_lifter_coverage.py - the reg,mem
  // direction of the same gap class as liftAddMem/liftSubMem.
  void liftAddRegMem(const llvm::MCInst &mc, std::uint64_t addr,
                     ignil::Block &out, std::uint32_t &tmp) const;
  void liftSubRegMem(const llvm::MCInst &mc, std::uint64_t addr,
                     ignil::Block &out, std::uint32_t &tmp) const;
  // reg op= [mem] for an XOR, AND or OR `op`, with the rr forms' flags.
  void liftLogicRegMem(const llvm::MCInst &mc, std::uint64_t addr,
                       ignil::Block &out, std::uint32_t &tmp,
                       ignil::Opcode op) const;
  // [mem] op= reg-or-imm, as liftLogicRegMem.
  void liftLogicMem(const llvm::MCInst &mc, std::uint64_t addr,
                    ignil::Block &out, std::uint32_t &tmp,
                    ignil::Opcode op) const;
  void liftXor(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
               std::uint32_t &tmp) const;
  void liftAnd(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
               std::uint32_t &tmp) const;
  void liftOr(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
              std::uint32_t &tmp) const;
  void liftPush(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                std::uint32_t &tmp) const;
  // PUSH [mem]: load, then as liftPush.
  void liftPushMem(const llvm::MCInst &mc, std::uint64_t addr,
                   ignil::Block &out, std::uint32_t &tmp) const;
  void liftPop(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
               std::uint32_t &tmp) const;
  // POP [mem]: as liftPop, then the store.
  void liftPopMem(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                  std::uint32_t &tmp) const;
  // POPFQ/PUSHFQ: pop RFLAGS off / push RFLAGS onto the stack, spreading the
  // popped value across (or gathering) the individual modeled flag registers.
  void liftPopf(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                std::uint32_t &tmp) const;
  void liftPushf(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                 std::uint32_t &tmp) const;
  // PUSHAD: push EAX, ECX, EDX, EBX, the original ESP, EBP, ESI and EDI.
  void liftPusha(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                 std::uint32_t &tmp) const;
  // POPAD: pop them back in reverse, skipping the saved ESP.
  void liftPopa(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                std::uint32_t &tmp) const;
  // PUSH / POP of a segment register (32-bit), e.g. `push ss`.
  void liftPushSeg(const llvm::MCInst &mc, std::uint64_t addr,
                   ignil::Block &out, std::uint32_t &tmp) const;
  void liftPopSeg(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                  std::uint32_t &tmp) const;
  void liftLea(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
               std::uint32_t &tmp) const;
  void liftCmp(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
               std::uint32_t &tmp) const;
  // CMP reg,mem: op[0]=reg(lhs), op[1..5]=mem(rhs). Loads rhs, discards the
  // SUB result, keeps the flags - same as liftCmp but rhs comes from memory.
  void liftCmpRegMem(const llvm::MCInst &mc, std::uint64_t addr,
                     ignil::Block &out, std::uint32_t &tmp) const;
  // CMP mem,reg / CMP mem,imm: op[0..4]=mem(lhs), op[5]=reg-or-imm(rhs).
  // Loads lhs, discards the SUB result, keeps the flags.
  void liftCmpMem(const llvm::MCInst &mc, std::uint64_t addr,
                  ignil::Block &out, std::uint32_t &tmp) const;
  void liftTest(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                std::uint32_t &tmp) const;
  // The target of a branch `offset` bytes past the end of the instruction at
  // `addr`, wrapped to 32 bits outside 64-bit mode.
  std::uint64_t pcRelTarget(std::uint64_t addr, std::uint8_t insnSize,
                            std::int64_t offset) const;
  void liftJcc(const llvm::MCInst &mc, std::uint64_t addr,
               std::uint8_t insnSize, ignil::Block &out,
               std::uint32_t &tmp) const;
  // LOOP: ECX (RCX in 64-bit mode) -= 1, then CJMP while it is non-zero.
  // With an address-size prefix the counter is CX (ECX in 64-bit mode).
  void liftLoop(const llvm::MCInst &mc, std::uint64_t addr,
                std::uint8_t insnSize, bool addressSizePrefix,
                ignil::Block &out, std::uint32_t &tmp) const;
  // Whether `insn` carries a 0x67 among its legacy prefixes.
  static bool hasAddressSizePrefix(const Instruction &insn);
  void liftJmp(const llvm::MCInst &mc, std::uint64_t addr,
               std::uint8_t insnSize, ignil::Block &out,
               std::uint32_t &tmp) const;
  void liftJmpMem(const llvm::MCInst &mc, std::uint64_t addr,
                  std::uint8_t insnSize, ignil::Block &out,
                  std::uint32_t &tmp) const;
  void liftCallMem(const llvm::MCInst &mc, std::uint64_t addr,
                   std::uint8_t insnSize, ignil::Block &out,
                   std::uint32_t &tmp) const;
  void liftCall(const llvm::MCInst &mc, std::uint64_t addr,
                std::uint8_t insnSize, ignil::Block &out,
                std::uint32_t &tmp) const;
  void liftRet(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
               std::uint32_t &tmp) const;
  void liftLeave(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                 std::uint32_t &tmp) const;
  // Widening move, MOVSX/MOVZX in both their register-source
  // (`movsxd rax, edi`) and memory-source (`movzx eax, byte ptr [rdi]`)
  // forms: op[0]=dst(wider), op[1]=src(narrower) or op[1..5]=mem.
  // No flags affected.
  //
  // Both facts come from the opcode, not the operands. The width, because a
  // memory reference carries no size of its own - only the MOVZX32rm8 /
  // MOVZX32rm16 spelling says how many bytes to load. And which form it is,
  // because op[1] is a register either way: for the rm forms it is the memory
  // operand's *base* register, so testing isReg() would silently take the
  // register path and drop the load. movzxForms_ / movsxForms_ hold both.
  //
  // The sign-extending form was found while lifting a real compiled
  // signed-division-by-constant sequence (GCC's standard multiply-high
  // lowering for `x / C`), not obfuscation-specific - it shows up in any
  // program that divides by a non-power-of-two constant. The memory-source
  // forms matter for bytecode dispatchers, where `movzx r32, [vip]` feeding
  // a handler-table index is the canonical opcode fetch.
  void liftMovExtend(const llvm::MCInst &mc, std::uint64_t addr,
                     MovExtendForm form, bool signExtend, ignil::Block &out,
                     std::uint32_t &tmp) const;
  // SAR by immediate: op[0]=dst(out), op[1]=src(tied=dst), op[2]=imm shift
  // count. Real x86: shift by 0 leaves every flag (and the value) untouched
  // - not even recomputed. CF = the last bit shifted out; SF/ZF as usual;
  // OF is only architecturally defined for a 1-bit shift (always 0 for
  // SAR specifically - an arithmetic right shift by exactly one bit can
  // never overflow), left UNDEF otherwise, matching this lifter's existing
  // "UNDEF for genuinely spec-undefined" convention rather than guessing.
  void liftSarImm(const llvm::MCInst &mc, std::uint64_t addr,
                  ignil::Block &out, std::uint32_t &tmp) const;
  // 3-operand signed multiply with immediate (e.g. `imul rax, rax, imm32`):
  // op[0]=dst, op[1]=src, op[2]=imm (already sign-extended to dst's width
  // by LLVM's own MCInst decode, same convention liftAdd already relies on
  // for ADD64ri32). All flags UNDEF: SF/ZF/AF/PF are architecturally
  // undefined for IMUL per the ISA spec, and CF/OF would need a full
  // double-width product to detect overflow correctly, which IGNIL's
  // fixed-width model doesn't support - left honestly UNDEF rather than a
  // guessed, likely-wrong formula.
  void liftImulImm(const llvm::MCInst &mc, std::uint64_t addr,
                   ignil::Block &out, std::uint32_t &tmp) const;
  // LEA computing a 64-bit address expression but writing only the 32-bit
  // low half of the destination (e.g. `lea eax, [rdx+rcx*1]` - address
  // registers are 64-bit, destination is 32-bit). Unlike liftLea, this
  // needs an explicit TRUNC: LLVMLifter's Reg-destination COPY only
  // widens (CreateZExt) when the source is narrower than the slot, and
  // would build invalid IR (or assert) if asked to narrow a 64-bit value
  // into a 32-bit slot directly.
  void liftLeaTrunc32(const llvm::MCInst &mc, std::uint64_t addr,
                      ignil::Block &out, std::uint32_t &tmp) const;
  // INC/DEC: op[0]=dst(out), op[1]=src(tied=dst), no immediate - implicit
  // +-1. Real x86: CF is left completely untouched (no Op emitted for it
  // at all, not even UNDEF - that's the whole point of INC/DEC over
  // ADD/SUB 1: they don't disturb a carry chain from a previous
  // instruction). OF: for INC, set iff the original value was the maximum
  // positive value for its width (wrapped to negative); for DEC, set iff
  // it was the minimum negative value (wrapped to non-negative).
  void liftInc(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
              std::uint32_t &tmp) const;
  void liftDec(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
              std::uint32_t &tmp) const;
  // NEG: op[0]=dst(out), op[1]=src(tied=dst). CF = (src != 0) - negating
  // zero doesn't borrow, anything else does. OF = (src was the minimum
  // negative value for its width - unrepresentable when negated).
  void liftNeg(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
              std::uint32_t &tmp) const;
  // SHL by immediate: op[0]=dst(out), op[1]=src(tied=dst), op[2]=imm shift
  // count. Same imm==0-leaves-everything-untouched rule as liftSarImm. CF
  // = the last bit shifted out the *top* (bit width-imm of the original
  // value, the opposite end from SAR/SHR). OF (count==1 only) = whether
  // the sign bit changed (result's sign XOR the original's sign) - SHL can
  // genuinely overflow either direction, unlike SAR/SHR.
  void liftShlImm(const llvm::MCInst &mc, std::uint64_t addr,
                  ignil::Block &out, std::uint32_t &tmp) const;
  // SHR by immediate: same shape as liftSarImm (CF = bit imm-1 of the
  // original value, same formula), but OF (count==1 only) = the sign bit
  // of the *original* value - a logical shift right always clears the new
  // sign bit, so "did the sign appear to change" reduces to whatever the
  // original sign bit was.
  void liftShrImm(const llvm::MCInst &mc, std::uint64_t addr,
                  ignil::Block &out, std::uint32_t &tmp) const;
  // 2-operand signed multiply (e.g. `imul eax, ebx`): op[0]=dst,
  // op[1]=src1(tied=dst), op[2]=src2(reg). Same all-UNDEF flag rationale as
  // liftImulImm - only the operand kind differs (register instead of imm).
  void liftImulRR(const llvm::MCInst &mc, std::uint64_t addr,
                  ignil::Block &out, std::uint32_t &tmp) const;
  // Shift-by-1 dedicated opcodes (e.g. `sar eax, 1`): op[0]=dst(out),
  // op[1]=src(tied=dst) - no immediate operand at all, the shift count of 1
  // is implicit in the opcode itself (distinct from SAR/SHL/SHR *ri with an
  // explicit imm operand). Each delegates to the corresponding liftXxxImm
  // by synthesizing a literal imm-1 operand, since the flag formulas are
  // identical once the count is known.
  void liftSarR1(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                 std::uint32_t &tmp) const;
  void liftShlR1(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                 std::uint32_t &tmp) const;
  void liftShrR1(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                 std::uint32_t &tmp) const;

  // LifterGaps.md #7 - forms VMProtect handlers are built from.
  // NOT: op[0]=dst(out), op[1]=src(tied=dst). Affects no flags.
  void liftNot(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
               std::uint32_t &tmp) const;
  // Shift by CL (SHL/SHR/SAR at 8/16/32/64): op[0]=dst(out),
  // op[1]=src(tied=dst); the count is CL masked to 5 bits (6 for 64-bit).
  // A zero count leaves every flag untouched, so CF/ZF/SF are merged with
  // their old value under an isZero mask; OF (count==1 only), PF and AF are
  // UNDEF. With memWidth the destination is memory (op[0..4]).
  void liftShiftCL(const llvm::MCInst &mc, std::uint64_t addr,
                   ignil::Block &out, std::uint32_t &tmp, ignil::Opcode shift,
                   std::optional<ignil::Width> memWidth = std::nullopt) const;
  // CBW/CWDE/CDQE sign-extend within RAX; CWD/CDQ/CQO sign-fill (R/E)DX
  // from the top bit of (R/E)AX. No operands, no flags.
  void liftAccExtend(std::uint64_t addr, ignil::Block &out,
                     std::uint32_t &tmp, AccExtend kind) const;
  // STC/CLC/CMC: set / clear / complement CF only.
  /// Which one-operand multiply / divide an opcode is, and at what width.
  struct MulDivForm {
    enum class Kind : std::uint8_t { Mul, Imul, Div, Idiv } kind;
    ignil::Width width;
  };

  /// SETcc r8: the register becomes 1 if the condition holds, else 0. Flags
  /// are read, not written.
  void liftSetcc(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                 std::uint32_t &tmp) const;
  /// ADC / SBB reg, reg/imm: `dst = dst +/- src +/- CF`, all six flags real.
  void liftAdcSbb(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                  std::uint32_t &tmp, bool isSbb) const;
  /// One-operand MUL / IMUL / DIV / IDIV on the accumulator pair. 8/16/32-bit
  /// forms are computed at twice the width; 64-bit MUL/IMUL build the high
  /// half from 32-bit partial products. 64-bit DIV/IDIV have a 128-bit
  /// dividend IGNIL cannot hold: their results are UNDEF and the instruction
  /// is recorded in Block::unlifted().
  void liftMulDiv(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                  std::uint32_t &tmp, MulDivForm form) const;
  /// BT reg, reg/imm8: CF = bit (index mod width) of the register. The other
  /// arithmetic flags are left as they were (ZF is documented unchanged, the
  /// rest undefined - and keeping them is one legal outcome of undefined).
  void liftBt(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
              std::uint32_t &tmp) const;
  // ROL/ROR, by imm8, by the implicit 1, or by CL. IGNIL has no rotate op,
  // so a rotate-left by c is synthesized as (x << c) | (x >> ((W - c) & (W-1)))
  // - the complementary amount masked to W-1 so a zero count shifts by 0, not
  // by W (poison), and reduces to x | x = x. Only CF and OF are affected:
  // CF = the bit rotated into the far end (gated, left untouched for a zero
  // count), OF defined only for a 1-bit rotate and otherwise UNDEF. SF/ZF/PF/AF
  // are not touched at all - a rotate does not disturb them. op[0]=dst(out),
  // op[1]=src(tied=dst), [op[2]=imm8] for the ri form. With memWidth the
  // destination is memory (op[0..4], [op[5]=imm8]).
  void liftRotate(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                  std::uint32_t &tmp, bool left, ShiftCount count,
                  std::optional<ignil::Width> memWidth = std::nullopt) const;
  // RCL/RCR by imm8 or by the implicit 1 (the CL forms stay unlifted: a
  // variable rotate through the carry is a (width+1)-bit rotation that does
  // not fit a 64-bit temp). With the count known at lift time, the result is a
  // fixed OR of at most three constant-shift terms - x shifted, CF inserted at
  // the seam, and x's wrap-around - each emitted only when its shift amount is
  // in range. Only CF (= the bit rotated into the far end) and OF (UNDEF,
  // defined only for a 1-bit rotate) are touched; a zero count changes
  // nothing. op[0]=dst(out), op[1]=src(tied=dst), [op[2]=imm8].
  void liftRotateCarry(const llvm::MCInst &mc, std::uint64_t addr,
                       ignil::Block &out, std::uint32_t &tmp, bool left,
                       ShiftCount count) const;
  // RCL/RCR by CL: the variable rotate through carry. The count is unknown at
  // lift time, so the result is built from the same three terms as the
  // immediate form but with runtime shift amounts - each kept in [0, W-1] (a
  // shift of exactly W is gated to 0) so none becomes poison, which is why a
  // (W+1)-bit container is avoided. The count is reduced with the real x86
  // rule (mask to 5/6 bits, then UMOD (W+1) for the 8/16-bit forms), and the
  // whole operation is gated by count != 0 - a zero count changes nothing.
  // Only CF (gated) and OF (UNDEF) are written.
  void liftRotateCarryCL(const llvm::MCInst &mc, std::uint64_t addr,
                         ignil::Block &out, std::uint32_t &tmp, bool left) const;
  // XCHG with the accumulator (XCHG16ar/XCHG32ar/XCHG64ar, `xchg ax/eax/rax,
  // r`): swap the explicit register op[0] with the width-matching accumulator.
  // No flags.
  void liftXchgAcc(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                   std::uint32_t &tmp) const;
  // BSF/BSR r,r: dst = index of the lowest (BSF) or highest (BSR) set bit of
  // the source; ZF = (source == 0), in which case dst is left at 0 (the ISA
  // leaves it undefined). Built as an unrolled "last write wins" scan over the
  // operand width - BSF scans high bit to low, BSR low to high - using the
  // mask-select idiom since IGNIL has no select. CF/OF/SF/AF/PF are UNDEF.
  void liftBitScan(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                   std::uint32_t &tmp, bool reverse) const;
  // BTS/BTR/BTC reg, reg/imm8: CF = the selected bit's old value, then that
  // bit of the register is set / cleared / complemented. The index wraps at
  // the operand width (register form) or is taken mod width (imm form). Like
  // liftBt, only CF is written; the other flags are left unchanged (ZF is
  // documented unchanged, the rest undefined - keeping them is one legal
  // outcome). op[0]=dst(out), op[1]=src(tied=dst), op[2]=bit index(reg/imm8).
  // With memWidth the destination is memory (op[0..4], op[5]=imm8 only; a
  // register index would address a bit string).
  void liftBitModify(const llvm::MCInst &mc, std::uint64_t addr,
                     ignil::Block &out, std::uint32_t &tmp, BitOp op,
                     std::optional<ignil::Width> memWidth = std::nullopt) const;
  // CMOVcc r,r: dst = cond ? src : dst. IGNIL has no select, so the result is
  // (src & m) | (dst & ~m) with m = all-ones when the condition holds. No
  // flags. op[0]=dst(out), op[1]=src1(tied=dst, the kept value), op[2]=src2
  // (the moved-in value), op[3]=condition code.
  void liftCmov(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                std::uint32_t &tmp) const;
  // XADD r,r: temp = dst + src; src = dst; dst = temp. The two registers are
  // op[0] (DEST) and op[1] (SRC); both are read before either is written, so
  // `xadd eax, eax` is handled. Flags are the plain ADD rules.
  void liftXadd(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                std::uint32_t &tmp) const;
  // INC/DEC with a memory destination: load, +/- 1, store back, then the same
  // flags as the register INC/DEC (CF deliberately untouched). op[0..4]=mem.
  void liftIncDecMem(const llvm::MCInst &mc, std::uint64_t addr,
                     ignil::Block &out, std::uint32_t &tmp, bool dec) const;
  // LAHF: AH = SF:ZF:0:AF:0:PF:1:CF (the low byte of RFLAGS). SAHF: set
  // SF/ZF/AF/PF/CF from the matching bits of AH. No other state changes.
  void liftLahf(std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftSahf(std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp) const;
  void liftCarryOp(std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp,
                   CarryOp kind) const;
  // CPUID / RDTSC / RDTSCP: instructions whose results x86 defines but IGNIL
  // cannot express. Emits one OPAQUE op per result register, all sharing the
  // same (snapshotted) operands, so the value is named rather than unknown -
  // two CPUIDs with the same leaf agree, while each RDTSC stays its own
  // reading. Before this they produced no IGNIL op at all: LLVM's MCInstrDesc
  // gives them no register defs, so even the UNDEF fallback did not fire and
  // the stale EAX/EDX silently survived the lift.
  void liftOpaque(std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp,
                  ignil::OpaqueKind kind) const;
  // PUSH imm8/imm32: the immediate is sign-extended to the stack width.
  void liftPushImm(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                   std::uint32_t &tmp) const;
  // XCHG r, r: swap two registers (no flags). op[0]/op[1] are the two
  // registers (LLVM lists both as defs, the tied uses follow).
  void liftXchg(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                std::uint32_t &tmp) const;
  // XCHG [mem], r: swap a register with memory (no flags).
  void liftXchgMem(const llvm::MCInst &mc, std::uint64_t addr,
                   ignil::Block &out, std::uint32_t &tmp) const;
  // BSWAP r32/r64: reverse the byte order (no flags). Built from
  // shift/and/or since IGNIL has no byte-swap primitive.
  void liftBswap(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                 std::uint32_t &tmp) const;
  // SHLD/SHRD by CL or imm8: op[0]=dst(out), op[1]=src1(tied=dst),
  // op[2]=src2, [op[3]=imm]. A zero count leaves dst and every flag alone,
  // expressed with all-ones/all-zero masks (IGNIL has no select).
  void liftShiftDouble(const llvm::MCInst &mc, std::uint64_t addr,
                       ignil::Block &out, std::uint32_t &tmp, bool left,
                       bool byCL) const;
  // Shared by the variable-count shifts: CF = last bit shifted out, ZF/SF
  // from the result, each merged with its old value when the count is zero;
  // OF/PF/AF UNDEF.
  void emitGatedShiftFlags(std::uint64_t addr, ignil::Block &out,
                           std::uint32_t &tmp, ignil::Temp lhs,
                           ignil::Temp cnt, ignil::Temp result,
                           bool leftShift) const;

  // Packed SSE uses snapshots of both 64-bit halves before updating any
  // destination. Every operation preserves EFLAGS; lane arithmetic wraps.
  enum class PackedKind {
    Move,
    MoveToXMM32,
    MoveToXMM64,
    MoveFromXMM32,
    MoveFromXMM64,
    Xor,
    And,
    Or,
    AndNot,
    Add32,
    Sub32,
    Mul32,
    Shuffle32,
    UnpackLow32,
    UnpackHigh32,
    UnpackLow64,
    UnpackHigh64,
    ShiftRightBytes,
    ShiftLeftBytes,
    ShiftRight32,
    ShiftLeft32,
    ShiftArith32
  };
  struct PackedForm {
    PackedKind kind;
    bool memory = false;
    bool store = false;
  };
  std::unordered_map<unsigned, PackedForm> packedForms_;
  void initializePackedSSE(const llvm::MCInstrInfo &info);
  [[nodiscard]] std::optional<std::array<ignil::Reg, 2>>
  xmmParts(unsigned llvmReg) const;
  void liftPackedSSE(const llvm::MCInst &mc, PackedForm form,
                     std::uint64_t addr, ignil::Block &out,
                     std::uint32_t &tmp) const;

  // Scalar-double operations update only the low half and preserve the high
  // half. MOVSD from memory instead clears the high half in the dispatcher.
  // These instructions do not affect EFLAGS.
  // op[0]=dst, op[1]=tied dst (preserved high half), op[2]=source.
  void liftCvtsi2sd(const llvm::MCInst &mc, std::uint64_t addr,
                    ignil::Block &out, std::uint32_t &tmp) const;
  void liftAddsd(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                std::uint32_t &tmp) const;
  void liftSubsd(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                std::uint32_t &tmp) const;
  void liftMulsd(const llvm::MCInst &mc, std::uint64_t addr, ignil::Block &out,
                std::uint32_t &tmp) const;
  // op[0]=dst(xmm), op[1]=tied(=dst, ignored), op[2..6]=mem(rhs) - mirrors
  // liftAddRegMem's shape (e.g. `mulsd xmm0, [rip+K]`, multiplying by a
  // compile-time double literal - ordinary code, not obfuscation-specific,
  // same story as item 15's division-by-constant lowering).
  void liftMulsdMem(const llvm::MCInst &mc, std::uint64_t addr,
                    ignil::Block &out, std::uint32_t &tmp) const;
  // op[0]=dst(GPR), op[1]=src(xmm) - not a tied form (an integer
  // destination has no partial-register-merge concern here).
  void liftCvttsd2si(const llvm::MCInst &mc, std::uint64_t addr,
                     ignil::Block &out, std::uint32_t &tmp) const;
  // op[0]=dst(xmm), op[1]=tied(=dst, ignored), op[2]=src(xmm) - real
  // hardware merges (preserves dst's upper 64 bits); reduces to a plain
  // copy of the low-half bank. liftMov's register form isn't
  // reusable as-is: its src operand is at index 1, not 2, since MOV64rr
  // has no tied-merge operand to skip over.
  void liftMovsdRR(const llvm::MCInst &mc, std::uint64_t addr,
                   ignil::Block &out, std::uint32_t &tmp) const;

  // Helpers
  // Translate an LLVM register integer to an ignil::Reg.
  // Returns nullopt for unknown registers (caller emits UNDEF).
  [[nodiscard]] std::optional<ignil::Reg> toReg(unsigned llvmReg) const;

  // Allocate a fresh temporary
  [[nodiscard]] ignil::Temp newTemp(std::uint32_t &tempId,
                                    ignil::Width width) const;

  // Decode the 5-operand x86 memory reference starting at
  // mc.getOperand(opStart) (base, scale, index, disp, seg) and emit the
  // arithmetic ops that compute the effective address, returning the Temp that
  // holds the result.
  [[nodiscard]] ignil::Temp emitAddress(const llvm::MCInst &mc,
                                        unsigned opStart, ignil::Width ptrWidth,
                                        std::uint64_t addr, ignil::Block &out,
                                        std::uint32_t &tmp,
                                        bool honorSegment = true) const;

  // Emit ops that compute the 1-bit boolean condition for a Jcc from the
  // current flag registers. condCode is the LLVM x86 CondCode immediate
  // (0-15) found in op[1] of the unified JCC_1/JCC_4 MCInst.
  [[nodiscard]] ignil::Temp emitCondition(unsigned condCode, std::uint64_t addr,
                                          ignil::Block &out,
                                          std::uint32_t &tmp) const;

  // Emit UNDEF for a destination register (conservative for
  // instructions we do not yet lift).
  void emitUndef(ignil::Reg dst, std::uint64_t addr, ignil::Block &out) const;

  // EFLAGS helpers - iterate every EFLAGS register; for each flag present in
  // flagMap the corresponding FlagSetter is called, otherwise UNDEF is emitted.
  void emitArithFlags(std::uint64_t addr, ignil::Block &out, std::uint32_t &tmp,
                      const std::map<X86Flag, FlagSetter> &flagMap = {}) const;

  // FlagSetter factories - each captures the operands it needs and returns a
  // callable suitable for the flagMap passed to emitArithFlags.

  // ZF = (value == 0)
  [[nodiscard]] FlagSetter zfEqZero(ignil::Value value,
                                    std::uint64_t addr) const;
  // SF = sign bit of value
  [[nodiscard]] FlagSetter sfSignBit(ignil::Value value,
                                     std::uint64_t addr) const;

  // CF = 0 / OF = 0  (logical ops: XOR, AND, OR, TEST always clear both)
  [[nodiscard]] FlagSetter cfAlwaysZero(std::uint64_t addr) const;
  [[nodiscard]] FlagSetter ofAlwaysZero(std::uint64_t addr) const;

  // PF = even parity of the low byte of the result. AF = carry out of bit 3
  // (bit 4 of lhs ^ rhs ^ result). Logical ops and shifts leave AF clear.
  // (LifterGaps.md #7 round 4: VMProtect derives branch targets from the
  // whole RFLAGS word, so PF/AF must be real bits, not UNDEF.)
  [[nodiscard]] FlagSetter pfParity(ignil::Value result, std::uint64_t addr) const;
  [[nodiscard]] FlagSetter afNibbleCarry(ignil::Value lhs, ignil::Value rhs,
                                         ignil::Value result,
                                         std::uint64_t addr) const;
  [[nodiscard]] FlagSetter afAlwaysZero(std::uint64_t addr) const;
  // The i1 parity bit itself (PF value) - shared by pfParity and the gated
  // shift flags.
  ignil::Temp parityBit(ignil::Value result, std::uint64_t addr,
                        ignil::Block &out, std::uint32_t &tmp) const;

  // CF for ADD: unsigned overflow  →  ULT(result, addend)
  [[nodiscard]] FlagSetter cfAddOverflow(ignil::Value result,
                                         ignil::Value addend,
                                         std::uint64_t addr) const;
  // CF for SUB/CMP: unsigned borrow  →  ULT(lhs, rhs)
  [[nodiscard]] FlagSetter cfSubBorrow(ignil::Value lhs, ignil::Value rhs,
                                       std::uint64_t addr) const;

  // OF for ADD: same-sign inputs produce opposite-sign result
  [[nodiscard]] FlagSetter ofAddOverflow(ignil::Value lhs, ignil::Value rhs,
                                         ignil::Value result,
                                         std::uint64_t addr) const;
  // OF for SUB/CMP: different-sign inputs, result sign differs from lhs
  [[nodiscard]] FlagSetter ofSubOverflow(ignil::Value lhs, ignil::Value rhs,
                                         ignil::Value result,
                                         std::uint64_t addr) const;

  // Cached opcode integers (same approach as X86Info)
  unsigned opMov64rr_{}, opMov32rr_{};
  unsigned opMov64ri_{}, opMov32ri_{}, opMov64ri32_{};
  unsigned opMov64rm_{}, opMov32rm_{}, opMov16rm_{}, opMov8rm_{};
  unsigned opMov64mr_{}, opMov32mr_{}, opMov16mr_{}, opMov8mr_{};
  unsigned opMov64mi_{}, opMov32mi_{}, opMov16mi_{}, opMov8mi_{};
  unsigned opLea64r_{}, opLea32r_{};
  unsigned opAdd64rr_{}, opAdd32rr_{};
  unsigned opAdd64ri_{}, opAdd32ri_{}, opAdd64ri8_{}, opAdd32ri8_{};
  unsigned opAdd64mr_{}, opAdd32mr_{}, opAdd8mr_{};
  unsigned opAdd64mi_{}, opAdd32mi_{}, opAdd64mi8_{}, opAdd32mi8_{};
  unsigned opAdd64rm_{}, opAdd32rm_{};
  unsigned opSub64rr_{}, opSub32rr_{};
  unsigned opSub64ri_{}, opSub32ri_{}, opSub64ri8_{}, opSub32ri8_{};
  unsigned opSub64mr_{}, opSub32mr_{};
  unsigned opSub64mi_{}, opSub32mi_{}, opSub64mi8_{}, opSub32mi8_{};
  unsigned opSub64rm_{}, opSub32rm_{};
  unsigned opXor64rr_{}, opXor32rr_{};
  unsigned opXor32rm_{}, opXor32mi_{}, opXor32mr_{};
  unsigned opXor32ri_{}, opXor64ri_{}, opXor32ri8_{}, opXor64ri8_{};
  unsigned opAnd64rr_{}, opAnd32rr_{};
  unsigned opAnd32mr_{};
  unsigned opAnd32ri_{}, opAnd64ri_{}, opAnd32ri8_{}, opAnd64ri8_{};
  unsigned opOr64rr_{}, opOr32rr_{};
  unsigned opOr32ri_{}, opOr64ri_{}, opOr32ri8_{}, opOr64ri8_{};
  unsigned opPush64r_{}, opPop64r_{};
  unsigned opPush32r_{}, opPop32r_{};
  unsigned opPush32rmm_{}, opPush64rmm_{}, opPop32rmm_{}, opPop64rmm_{};
  unsigned opPopf64_{}, opPopf32_{}, opPushf64_{}, opPushf32_{};
  unsigned opPusha32_{}, opPopa32_{};
  unsigned opPushSS32_{}, opPopSS32_{};
  unsigned opCmp64rr_{}, opCmp32rr_{};
  unsigned opCmp64ri_{}, opCmp32ri_{}, opCmp64ri8_{}, opCmp32ri8_{};
  unsigned opCmp64rm_{}, opCmp32rm_{};
  unsigned opCmp64mr_{}, opCmp32mr_{};
  unsigned opCmp64mi_{}, opCmp32mi_{}, opCmp64mi8_{}, opCmp32mi8_{};
  unsigned opCmp8mi_{};
  unsigned opTest64rr_{}, opTest32rr_{};
  unsigned opTest32ri_{}, opTest64ri_{};
  unsigned opJmp64r_{}, opJmp32r_{}; // indirect
  unsigned opJmp64m_{}, opJmp32m_{}; // indirect memory jump
  unsigned opCall64m_{}, opCall32m_{}; // indirect memory call
  unsigned opJmp_{}; // direct
  unsigned opLoop_{};
  unsigned opCall64r_{}, opCall32r_{}; // indirect
  unsigned opCall_{}, opCall32_{}; // direct
  unsigned opRet64_{}, opRet32_{};
  unsigned opRetI64_{}, opRetI32_{}; // ret N  (callee-cleanup variant)
  unsigned opLeave64_{}, opLeave_{}; // leave (decomposed to mov rsp,rbp / pop rbp)
  unsigned opSar32ri_{}, opSar64ri_{};
  unsigned opImul64rri32_{}, opImul64rri8_{}, opImul32rri_{}, opImul32rri8_{};
  unsigned opImul32rr_{}, opImul64rr_{};
  unsigned opLea64_32r_{};
  unsigned opInc32r_{}, opInc64r_{}, opDec32r_{}, opDec64r_{};
  unsigned opInc32r_alt_{}, opDec32r_alt_{}; // 0x40+r / 0x48+r, 32-bit only
  unsigned opNeg32r_{}, opNeg64r_{};
  unsigned opShl32ri_{}, opShl64ri_{}, opShr32ri_{}, opShr64ri_{};
  unsigned opSar32r1_{}, opSar64r1_{}, opShl32r1_{}, opShl64r1_{},
          opShr32r1_{}, opShr64r1_{};
  // LifterGaps.md #7 (VMProtect handler forms).
  unsigned opNot8r_{}, opNot16r_{}, opNot32r_{}, opNot64r_{};
  unsigned opNeg8r_{}, opNeg16r_{};
  unsigned opShl8ri_{}, opShl16ri_{}, opShr8ri_{}, opShr16ri_{}, opSar8ri_{},
          opSar16ri_{};
  unsigned opShl8r1_{}, opShl16r1_{}, opShr8r1_{}, opShr16r1_{}, opSar8r1_{},
          opSar16r1_{};
  unsigned opShl8rCL_{}, opShl16rCL_{}, opShl32rCL_{}, opShl64rCL_{};
  unsigned opShr8rCL_{}, opShr16rCL_{}, opShr32rCL_{}, opShr64rCL_{};
  unsigned opShr32mCL_{};
  unsigned opSar8rCL_{}, opSar16rCL_{}, opSar32rCL_{}, opSar64rCL_{};
  unsigned opCbw_{}, opCwde_{}, opCdqe_{}, opCwd_{}, opCdq_{}, opCqo_{};
  unsigned opStc_{}, opClc_{}, opCmc_{}, opCld_{};
  unsigned opSetccr_{};
  unsigned opBt16ri8_{}, opBt32ri8_{}, opBt64ri8_{};
  unsigned opBt16rr_{}, opBt32rr_{}, opBt64rr_{};
  // Rotates (LifterGaps.md: VMProtect mutation handlers).
  unsigned opRol8ri_{}, opRol16ri_{}, opRol32ri_{}, opRol64ri_{};
  unsigned opRol8r1_{}, opRol16r1_{}, opRol32r1_{}, opRol64r1_{};
  unsigned opRol8rCL_{}, opRol16rCL_{}, opRol32rCL_{}, opRol64rCL_{};
  unsigned opRor8ri_{}, opRor16ri_{}, opRor32ri_{}, opRor64ri_{};
  unsigned opRor8r1_{}, opRor16r1_{}, opRor32r1_{}, opRor64r1_{};
  unsigned opRor8rCL_{}, opRor16rCL_{}, opRor32rCL_{}, opRor64rCL_{};
  unsigned opRor32mCL_{};
  // Rotate through carry, imm8 and by-1 forms only (see liftRotateCarry).
  unsigned opRcl8ri_{}, opRcl16ri_{}, opRcl32ri_{}, opRcl64ri_{};
  unsigned opRcl8r1_{}, opRcl16r1_{}, opRcl32r1_{}, opRcl64r1_{};
  unsigned opRcr8ri_{}, opRcr16ri_{}, opRcr32ri_{}, opRcr64ri_{};
  unsigned opRcr8r1_{}, opRcr16r1_{}, opRcr32r1_{}, opRcr64r1_{};
  // Rotate through carry by CL (variable count; see liftRotateCarryCL).
  unsigned opRcl8rCL_{}, opRcl16rCL_{}, opRcl32rCL_{}, opRcl64rCL_{};
  unsigned opRcr8rCL_{}, opRcr16rCL_{}, opRcr32rCL_{}, opRcr64rCL_{};
  // XCHG with the accumulator.
  unsigned opXchg16ar_{}, opXchg32ar_{}, opXchg64ar_{};
  // Bit scan forward / reverse, reg,reg.
  unsigned opBsf16rr_{}, opBsf32rr_{}, opBsf64rr_{};
  unsigned opBsr16rr_{}, opBsr32rr_{}, opBsr64rr_{};
  // Bit test-and-modify (BTS/BTR/BTC), register and imm8 index.
  unsigned opBts16ri8_{}, opBts32ri8_{}, opBts64ri8_{};
  unsigned opBts16rr_{}, opBts32rr_{}, opBts64rr_{};
  unsigned opBtr16ri8_{}, opBtr32ri8_{}, opBtr64ri8_{};
  unsigned opBtr32mi8_{};
  unsigned opBtr16rr_{}, opBtr32rr_{}, opBtr64rr_{};
  unsigned opBtc16ri8_{}, opBtc32ri8_{}, opBtc64ri8_{};
  unsigned opBtc16rr_{}, opBtc32rr_{}, opBtc64rr_{};
  // CMOVcc (unified LLVM opcode with a condition-code operand), reg,reg.
  unsigned opCmov16rr_{}, opCmov32rr_{}, opCmov64rr_{};
  // XADD reg,reg.
  unsigned opXadd8rr_{}, opXadd16rr_{}, opXadd32rr_{}, opXadd64rr_{};
  // INC/DEC with a memory destination.
  unsigned opInc8m_{}, opInc16m_{}, opInc32m_{}, opInc64m_{};
  unsigned opDec8m_{}, opDec16m_{}, opDec32m_{}, opDec64m_{};
  // MOV r8(high), imm8 - the alternate encoding LLVM names MOV8ri_alt.
  unsigned opMov8riAlt_{};
  // LAHF / SAHF.
  unsigned opLahf_{}, opSahf_{};
  unsigned opCpuid_{}, opRdtsc_{}, opRdtscp_{};
  // push imm (LifterGaps.md #7 round 3)
  unsigned opPush32I_{}, opPush32I8_{}, opPush64I32_{}, opPush64I8_{};
  // LifterGaps.md #7 round 2: 8/16-bit ALU forms, XCHG, BSWAP, SHLD/SHRD.
  unsigned opMov8rr_{}, opMov16rr_{}, opMov8ri_{}, opMov16ri_{};
  unsigned opAdd8rr_{}, opAdd16rr_{}, opAdd8ri_{}, opAdd16ri_{}, opAdd8ri8_{},
          opAdd16ri8_{};
  unsigned opSub8rr_{}, opSub16rr_{}, opSub8ri_{}, opSub16ri_{}, opSub8ri8_{},
          opSub16ri8_{};
  unsigned opAnd8rr_{}, opAnd16rr_{}, opAnd8ri_{}, opAnd16ri_{}, opAnd8ri8_{},
          opAnd16ri8_{};
  unsigned opOr8rr_{}, opOr16rr_{}, opOr8ri_{}, opOr16ri_{}, opOr8ri8_{},
          opOr16ri8_{};
  unsigned opXor8rr_{}, opXor16rr_{}, opXor8ri_{}, opXor16ri_{}, opXor8ri8_{},
          opXor16ri8_{};
  unsigned opCmp8rr_{}, opCmp16rr_{}, opCmp8ri_{}, opCmp16ri_{}, opCmp8ri8_{},
          opCmp16ri8_{};
  unsigned opTest8rr_{}, opTest16rr_{}, opTest8ri_{}, opTest16ri_{};
  unsigned opInc8r_{}, opInc16r_{}, opDec8r_{}, opDec16r_{};
  unsigned opInc16r_alt_{}, opDec16r_alt_{}; // 66 40+r / 66 48+r, 32-bit only
  unsigned opXchg8rr_{}, opXchg16rr_{}, opXchg32rr_{}, opXchg64rr_{};
  unsigned opXchg32rm_{}, opXchg8rm_{};
  unsigned opBswap32r_{}, opBswap64r_{};
  unsigned opShld16rrCL_{}, opShld32rrCL_{}, opShld64rrCL_{}, opShrd16rrCL_{},
          opShrd32rrCL_{}, opShrd64rrCL_{};
  unsigned opShld16rri8_{}, opShld32rri8_{}, opShld64rri8_{}, opShrd16rri8_{},
          opShrd32rri8_{}, opShrd64rri8_{};
  // MOVZX/MOVSX opcode -> how to lift it. Every variant LLVM decodes is in
  // here, register- and memory-source alike, so a spelling that is not covered
  // fails loud (UNDEF from liftInstruction's default case) rather than being
  // lifted at the wrong width or off the wrong operand.
  std::unordered_map<unsigned, MovExtendForm> movzxForms_;
  std::unordered_map<unsigned, MovExtendForm> movsxForms_;

  // Load-direction reg-reg encodings (0x8B/0x03/0x33/... with mod=11) decode
  // to distinct LLVM *_REV opcodes (e.g. MOV32rr_REV, ADD32rr_REV) that carry
  // the SAME MCInst operand order as their base form. Compilers emit these
  // constantly, so map each *_REV opcode to its base and normalize in
  // liftInstruction() before dispatch. Without this they hit the default case
  // and lift to UNDEF (found via symbolic-execution differential testing).
  std::unordered_map<unsigned, unsigned> revToBase_;

  unsigned opCvtsi2sd32_{}, opCvtsi2sd64_{};
  unsigned opCvttsd2si32_{}, opCvttsd2si64_{};
  unsigned opAddsd_{}, opSubsd_{}, opMulsd_{}, opMulsdMem_{};
  unsigned opMovsdRR_{}, opMovsdLoad_{}, opMovsdStore_{};

  // LLVM register integer -> ignil::Reg mapping
  // Built once in constructor by scanning MCRegisterInfo +
  // the static name->offset table:
  std::unordered_map<unsigned, ignil::Reg> regMap_;

  // Well-known IGNIL Reg object for flags (generated
  // in the constructor by name).
  ignil::Reg regCF_{}, regPF_{}, regAF_{};
  ignil::Reg regZF_{}, regSF_{}, regOF_{}, regDF_{};
  ignil::Reg regRSP_{}, regESP_{}; // needed for push/pop/leave
  ignil::Reg regRIP_{}; // pinned to the next address for RIP-relative operands
  ignil::Reg regAH_{}; // remainder of an 8-bit DIV/IDIV
  ignil::Reg regFSBASE_{}, regGSBASE_{};
  unsigned llvmFS_ = 0, llvmGS_ = 0;
  unsigned llvmEflags_ = 0; ///< LLVM's number for EFLAGS (not an IGNIL register).

  /// ADC / SBB register forms: opcode -> true for SBB.
  std::unordered_map<unsigned, bool> adcSbbForms_;

  /// One-operand MUL / IMUL / DIV / IDIV, register forms.
  std::unordered_map<unsigned, MulDivForm> mulDivForms_;

  /// An accumulator short form (`sub al, imm8`, `cmp eax, imm32`, ...) and the
  /// generic reg-imm opcode that means the same thing. The short forms carry
  /// the immediate as their only MCInst operand - the register is implicit -
  /// so liftInstruction rebuilds them as the generic form and every ALU lifter
  /// handles them without knowing they exist.
  struct AccForm {
    unsigned genericOpcode;
    unsigned llvmReg; ///< LLVM register number of AL / AX / EAX / RAX.
    bool tiedDst; ///< Generic form is (dst, src1=dst, imm) rather than (lhs, imm).
  };
  std::unordered_map<unsigned, AccForm> accForms_;
  ignil::Reg regRBP_{}, regEBP_{}; // needed for leave decomposition
  // CL as a shift count; accumulator/data registers for CBW..CQO.
  ignil::Reg regCL_{}, regAL_{}, regAX_{}, regEAX_{}, regRAX_{}, regDX_{},
          regEDX_{}, regRDX_{};
  // CPUID/RDTSCP also define EBX and ECX.
  ignil::Reg regEBX_{}, regECX_{};
  // PUSHAD/POPAD also save and restore ESI and EDI.
  ignil::Reg regESI_{}, regEDI_{};
  // LOOP's counter in 64-bit mode, and with an address-size prefix.
  ignil::Reg regRCX_{}, regCX_{};
};

} // namespace x86
} // namespace dragon
