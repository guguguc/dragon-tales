#include "Passes.hpp"

#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/ScalarEvolution.h>
#include <llvm/Analysis/ScalarEvolutionExpressions.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>

namespace {
class CoalesceAffineIVsPass
    : public llvm::PassInfoMixin<CoalesceAffineIVsPass> {
  public:
  llvm::PreservedAnalyses run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &manager) {
    auto &loops = manager.getResult<llvm::LoopAnalysis>(function);
    auto &evolution =
            manager.getResult<llvm::ScalarEvolutionAnalysis>(function);
    // Plan before mutation: a discarded PHI's SCEV must never be consulted
    // after rewriting it. At most one elimination per loop per invocation.
    struct Rewrite {
      llvm::PHINode *keep, *remove;
      llvm::APInt offset;
    };
    llvm::SmallVector<Rewrite, 4> rewrites;
    for (auto *loop: loops.getLoopsInPreorder()) {
      bool found = false;
      for (auto &keep: loop->getHeader()->phis()) {
        if (!keep.getType()->isIntegerTy())
          continue;
        auto *recurrence =
                llvm::dyn_cast<llvm::SCEVAddRecExpr>(evolution.getSCEV(&keep));
        if (!recurrence || recurrence->getLoop() != loop ||
            !recurrence->isAffine())
          continue;
        for (auto &remove: loop->getHeader()->phis()) {
          if (&remove == &keep || keep.getType() != remove.getType() ||
              !keep.getType()->isIntegerTy())
            continue;
          auto *other = llvm::dyn_cast<llvm::SCEVAddRecExpr>(
                  evolution.getSCEV(&remove));
          if (!other || other->getLoop() != loop || !other->isAffine())
            continue;
          auto *difference = llvm::dyn_cast<llvm::SCEVConstant>(
                  evolution.getMinusSCEV(other, recurrence));
          if (!difference)
            continue;
          rewrites.push_back({&keep, &remove, difference->getAPInt()});
          found = true;
          break;
        }
        if (found)
          break;
      }
    }
    for (auto &rewrite: rewrites) {
      llvm::IRBuilder<> builder(rewrite.keep->getParent(),
                                rewrite.keep->getParent()->getFirstNonPHIIt());
      auto *replacement = builder.CreateAdd(
              rewrite.keep,
              llvm::ConstantInt::get(rewrite.keep->getType(), rewrite.offset),
              "iv.offset");
      rewrite.remove->replaceAllUsesWith(replacement);
      rewrite.remove->eraseFromParent();
    }
    return rewrites.empty() ? llvm::PreservedAnalyses::all()
                            : llvm::PreservedAnalyses::none();
  }
};

// Presentation only. Proof-carrying input names and metadata live in the
// preceding artifact; the caller separately verifies the cleaned CFG.
class CleanIRNamesPass : public llvm::PassInfoMixin<CleanIRNamesPass> {
  public:
  llvm::PreservedAnalyses run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &manager) {
    auto &loops = manager.getResult<llvm::LoopAnalysis>(function);
    auto &evolution =
            manager.getResult<llvm::ScalarEvolutionAnalysis>(function);
    llvm::SmallVector<llvm::StringRef, 32> kinds;
    function.getContext().getMDKindNames(kinds);
    for (auto &block: function) {
      block.setName("");
      for (auto &instruction: block) {
        instruction.setName("");
        for (unsigned id = 0; id < kinds.size(); ++id)
          if (kinds[id].starts_with("dragon."))
            instruction.setMetadata(id, nullptr);
      }
    }
    unsigned number = 0;
    for (auto &block: function) {
      auto *loop = loops.getLoopFor(&block);
      block.setName(&block == &function.getEntryBlock() ? "entry"
                    : loop && loop->getHeader() == &block
                            ? "loop"
                            : "bb" + std::to_string(++number));
      for (auto &phi: block.phis()) {
        auto *recurrence = phi.getType()->isIntegerTy()
                                   ? llvm::dyn_cast<llvm::SCEVAddRecExpr>(
                                             evolution.getSCEV(&phi))
                                   : nullptr;
        phi.setName(loop && loop->getHeader() == &block
                            ? recurrence && recurrence->isAffine() ? "iv"
                                                                   : "acc"
                            : "merge");
      }
    }
    return llvm::PreservedAnalyses::all();
  }
};
} // namespace

void dragon::llvmlifter::registerLoopCleanupPass(llvm::PassBuilder &builder) {
  builder.registerPipelineParsingCallback(
          [](llvm::StringRef name, llvm::FunctionPassManager &passes,
             llvm::ArrayRef<llvm::PassBuilder::PipelineElement> inner) {
            if (!inner.empty())
              return false;
            if (name == "dragon-coalesce-affine-ivs")
              passes.addPass(CoalesceAffineIVsPass());
            else if (name == "dragon-clean-ir-names")
              passes.addPass(CleanIRNamesPass());
            else
              return false;
            return true;
          });
}
