#pragma once

#include <dragon/Architecture.hpp>
#include <dragon/disassembler/Function.hpp>
#include <dragon/disassembler/Graph.hpp>
#include <dragon/lifters/ignil/IGNIL.hpp>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <cstddef>
#include <map>
#include <memory>
#include <string>
#include <string_view>

namespace z3 { class expr; }
namespace dragon::ignil { class MemoryEffects; }

namespace dragon::llvmlifter {

/// One context-sensitive step of a symbolically resolved x86-64 path.
/// Bodies are borrowed for the duration of liftPath(); null means an empty body.
/// Transfers were handled outside IGNIL by the explorer. CALL pushes the native
/// return address; RETURN pops it plus stackAdjustment. A returned address and
/// any IGNIL branch target are guarded with llvm.assume, not silently discarded.
struct ResolvedPathStep {
  enum class Transfer : std::uint32_t { Next = 0, Call = 1, Return = 2 };
  const ignil::Block *body = nullptr;
  std::uint64_t address = 0;
  std::uint64_t nextAddress = 0;
  Transfer transfer = Transfer::Next;
  std::uint64_t returnAddress = 0;
  std::uint32_t stackAdjustment = 0;
};


class LLVMLifter {
  public:
  explicit LLVMLifter(Architecture arch,
                      std::string_view moduleName = "lifted");
  ~LLVMLifter();

  LLVMLifter(const LLVMLifter &) = delete;
  LLVMLifter &operator=(const LLVMLifter &) = delete;
  LLVMLifter(LLVMLifter &&) noexcept;
  LLVMLifter &operator=(LLVMLifter &&) noexcept = default;

  /// Lift one function (all its IGNIL blocks must be in the graph).
  bool lift(const Function &fn, const Graph &graph);

  /// Lifts a single, already-flattened IGNIL block directly to LLVM IR -
  /// no Graph/Function needed. This is the Graph-free counterpart to
  /// Disassembler::liftTrace(): a linear, already-resolved execution trace
  /// has no unresolved branch left to encode (the block's op order *is*
  /// the path that was actually taken), so JMP/CJMP ops - which liftTrace
  /// still emits per-instruction, same as normal lifting - are dropped
  /// rather than translated, instead of producing `unreachable` (their
  /// fate under the Graph-based `lift()` when a target isn't in the
  /// function). CALL is preserved as a real LLVM call. RET, if present,
  /// must be the block's true terminator - anything after it is ignored,
  /// matching how a real `ret` would end execution. If the block has no
  /// RET, a synthetic `ret void` (with the usual register write-back) is
  /// appended so the function is always well-formed.
  ///
  /// Returns false for an empty block.
  bool liftBlock(const ignil::Block &block, std::string_view name = "trace");

  /// Export a finite resolved path, retaining the actual IGNIL bodies and a
  /// separate LLVM block per occurrence (including repeated source PCs). This
  /// is path-specialized IR, not an all-path CFG reconstruction. Inputs remain
  /// (mem, regs); capture memory and opaque observations are not embedded.
  /// x86-64 only. The last step must be a Return; invalid input adds no function.
  bool liftPath(const std::vector<ResolvedPathStep> &steps,
                std::string_view name = "resolved_path");

#ifdef DRAGON_WITH_Z3
  /// Explicit, topologically ordered scalar call results recovered at native
  /// function boundaries. Callees must already be defined in this module.
  struct ExpressionCall {
    const z3::expr *result;
    std::string function;
    std::vector<z3::expr> arguments;
  };

  /// Lower a recovered pure return-value DAG, not the native execution path.
  /// Arguments must be distinct named Bool/BitVec constants in expression's
  /// context. All dependencies must be arguments or supported total operations;
  /// unknown memory/opaque/UNDEF symbols are rejected, never replaced by zero.
  /// No pattern matching of algorithms or solver-model concretization is used.
  /// Result is a typed pure LLVM function. The caller records capture/path and
  /// side-effect scope separately. Invalid input leaves the module unchanged.
  bool liftExpression(const z3::expr &expression,
                      const std::vector<z3::expr> &arguments,
                      std::string_view name = "recovered");
  /// Same projection with explicit call-result bindings; keeps the existing
  /// three-argument entry point and its ABI intact.
  bool liftExpression(const z3::expr &expression,
                      const std::vector<z3::expr> &arguments,
                      std::string_view name,
                      const std::vector<ExpressionCall> &calls);

  /// Export a pure state region: while (continue(state, inputs)) state=next.
  /// Carried variables are simultaneous PHIs, not sequential substitutions.
  /// Returns the current header state when continuation is false. The caller
  /// separately proves the entry invariant/termination and supplies the exit
  /// projection (which may execute the final native traversal). Not a complete
  /// original function or an implicit caller-visible-memory projection.
  bool liftLoopRegion(const std::vector<z3::expr> &inputs,
                      const std::vector<z3::expr> &carried,
                      const std::vector<z3::expr> &next,
                      const z3::expr &continuation,
                      std::string_view name = "loop_region");

  /// Build a scalar-return loop from recovered DAGs. Initial values depend
  /// only on inputs; next/condition/return may additionally use simultaneous
  /// carried PHIs. No affine-counter, fixed-trip or termination assumption.
  /// Optional entryGuard/otherwise form a real outer branch, not an assume.
  /// Projects a pure return; memory effects/reachability remain caller-owned.
  bool liftLoopFunction(const std::vector<z3::expr> &inputs,
                        const std::vector<z3::expr> &carried,
                        const std::vector<z3::expr> &initial,
                        const std::vector<z3::expr> &next,
                        const z3::expr &continuation,
                        const z3::expr &returned,
                        std::string_view name = "recovered_loop",
                        const z3::expr *entryGuard = nullptr,
                        const z3::expr *otherwise = nullptr);

  /// Export a finite resolved effect sequence plus optional return (null=void).
  /// Pointer arguments are BV64 source symbols exported as ptr. All loads and
  /// stores share one address space; no noalias, inbounds or capture-value
  /// specialization. Alignment is 1. Only ordinary, valid, nonvolatile x86-64
  /// memory is modeled; not MMIO, atomics, concurrent/fault behavior or all paths.
  /// Surviving unknown dependencies fail instead of being concretized.
  bool liftEffects(const z3::expr *expression,
                   const std::vector<z3::expr> &arguments,
                   const std::vector<bool> &pointerArguments,
                   const ignil::MemoryEffects &effects,
                   std::string_view name = "recovered");
#endif

  /// Run LLVM PassBuilder syntax (e.g. default<O2> or
  /// function(instcombine,dce)). Verify before/after and commit a cloned module
  /// only on success. Failure keeps the original module; optional diagnostics
  /// are cleared on success. Structural verification is not a
  /// semantic-equivalence proof.
  bool runPassPipeline(std::string_view pipeline, std::string *error = nullptr);
  [[nodiscard]] bool verify(std::string *error = nullptr) const;

  // Run optimization passes in the recommended order.
  void runMem2Reg(); // promotes allocas → SSA, inserts PHIs
  void runInstCombine(); // folds sub-register mask/OR patterns
  void runGVN(); // eliminates redundant loads
  void runDCE(); // removes dead flag computations

  /// Parse and verify textual IR into this context; failure keeps the module.
  bool loadIR(std::string_view text);
  /// Post-optimization fixed-trip reroll of closed scalar integer chains.
  /// Exact structural matching (including flags); no VM/VIP/source assumptions.
  /// Returns the number of loops created. Parameter-bound loop recovery is
  /// separate; memory, calls, vectors, freeze and external intermediate uses
  /// are excluded. Cost-budget exhaustion leaves unmatched code unchanged.
  std::size_t runLoopReroll();

  [[nodiscard]] std::string ir() const; // dump textual LLVM IR
  [[nodiscard]] llvm::Module &module();

  /// Recover `fn`'s prototype (arguments + return) for this lifter's
  /// architecture and render it as a C-like string, e.g.
  /// `i32 sub_1000(i32 RDI, i32 RSI)`. This is the same recovery lift()
  /// records on each lifted function as a "dragon.signature" attribute;
  /// exposed here so a caller can get the prototype without parsing the IR.
  /// See dragon::analysis::recoverSignature for the method and its limits.
  [[nodiscard]] std::string recoveredSignatureString(const Function &fn,
                                                     const Graph &graph) const;

  private:
  // All allocas for a lifted function.
  // In this way we keep the registers that have been
  // used, and we only generate those that are used by
  // the function.
  // map<register offset, map<bit width, AllocaInst>>
  using RegFile =
          std::map<std::uint32_t, std::map<ignil::Width, llvm::AllocaInst *>>;

  // SSA values produced by Temp operands within the current block.
  using TempMap = std::map<std::uint32_t, llvm::Value *>;

  // First pass: scan every IGNIL op in every block of the function,
  // collect all (offset, width) pairs, emit one alloca per pair
  // in the entry block.
  RegFile buildRegFile(llvm::Function *llfn, const Function *fn,
                       const Graph &graph) const;

  // Shared by buildRegFile() and liftBlock(): scan `ops`, recording every
  // (offset, width) Reg pair referenced (as dst or src) into `regFile`
  // (value left null - allocateRegFile fills it in) and any name seen.
  // Not static: on x86-64 a 32-bit destination also needs its 64-bit parent
  // slot, which depends on the architecture being lifted.
  void collectRegsFromOps(
          const std::vector<ignil::Op> &ops, RegFile &regFile,
          std::map<std::pair<std::uint32_t, ignil::Width>, std::string_view>
                  &regNames) const;

  // Shared by buildRegFile() and liftBlock(): given a regFile whose
  // (offset, width) keys are already collected, create one alloca per pair
  // at the entry block's insertion point, named from `regNames` where
  // known.
  void allocateRegFile(
          llvm::Function *llfn, RegFile &regFile,
          const std::map<std::pair<std::uint32_t, ignil::Width>,
                         std::string_view> &regNames) const;

  // Shared by liftOp()'s RET case and liftBlock()'s synthetic-return
  // fallback: write the widest register at each offset back to `regsPtr`
  // and terminate the current block with `ret void`.
  void emitReturn(RegFile &regs, llvm::Value *regsPtr,
                  llvm::IRBuilder<> &builder);

  // Map each IGNIL block address to a llvm::BasicBlock.
  // Returns nullopt if any block in fn is missing an IGNIL translation,
  // since the function cannot be correctly lifted with a gap.
  std::optional<std::map<std::uint64_t, llvm::BasicBlock *>>
  buildBlockMap(llvm::Function *llfn, const Function *fn,
                const Graph &graph) const;

  // Translate one IGNIL block into its llvm::BasicBlock.
  void liftBlock(const ignil::Block *ib, llvm::Function *llfn, RegFile *regs,
                 TempMap *temps, llvm::Value *memPtr, llvm::Value *regsPtr,
                 const std::map<std::uint64_t, llvm::BasicBlock *> &bbMap);

  // Translate one IGNIL Op; records the result in temps if the op has a
  // Temp destination
  void liftOp(const ignil::Op &op, RegFile &regs, TempMap &temps,
              llvm::Value *memPtr, llvm::Value *regsPtr,
              llvm::IRBuilder<> &builder,
              const std::map<std::uint64_t, llvm::BasicBlock *> &bbMap);

  // Resolve an ignil::Value to a llvm::Value (load from alloca or
  // look up the temp SSA value).
  llvm::Value *resolve(const ignil::Value &v, RegFile &regs,
                       const TempMap &temps, llvm::IRBuilder<> &builder) const;

  // After writing `value` (of `width` bits) to `offset`, propagate
  // into every other alloca that exists at the same offset: merged into
  // the wider ones, truncated into the narrower ones.
  void mergeIntoParent(std::uint32_t offset, ignil::Width width,
                       llvm::Value *value, RegFile &regs,
                       llvm::IRBuilder<> &builder);

  // Prologue: load each register's initial value from %regs and store into
  // its alloca. Sub-register allocas are initialized by truncating the widest
  // value at the same offset.
  void initializeRegistersFromParam(llvm::Function *llfn, RegFile &regFile,
                                    llvm::Value *regsPtr);

  Architecture arch_;
  std::unique_ptr<llvm::LLVMContext> ctx_;
  std::unique_ptr<llvm::Module> module_;
};

} // namespace dragon::llvmlifter
