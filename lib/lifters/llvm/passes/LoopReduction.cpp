#include "Passes.hpp"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallBitVector.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/ValueHandle.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Transforms/Utils/Local.h>

#include <utility>

namespace {
// Quotient independent, wrapping integer ADD recurrences by their sum. No
// source formula, lane count, induction variable or VM register is assumed.
// All observations must use EVERY selected accumulator exactly once, through
// unflagged ADDs or selects with identical lane sets. Individual observations,
// cross-lane feedback and partial reductions fail closed. In particular we do
// not reassociate flagged arithmetic, freeze, loads, calls or floating point.
struct Reduction {
  llvm::PHINode *phi;
  llvm::BinaryOperator *update;
  llvm::Value *seed;
  llvm::Value *delta;
};

bool wrappingAdd(const llvm::Instruction *instruction) {
  const auto *add = llvm::dyn_cast<llvm::BinaryOperator>(instruction);
  return add && add->getOpcode() == llvm::Instruction::Add &&
         !add->hasNoSignedWrap() && !add->hasNoUnsignedWrap() &&
         !add->hasMetadataOtherThanDebugLoc();
}

class AddReduction {
  llvm::Loop &loop_;
  llvm::SmallVector<Reduction, 8> reductions_;
  llvm::SmallPtrSet<llvm::Value *, 32> affected_;
  llvm::DenseMap<llvm::Value *, llvm::SmallBitVector> forms_;
  llvm::SmallPtrSet<llvm::Value *, 32> visiting_;
  llvm::SmallPtrSet<llvm::Value *, 32> boundaries_;
  llvm::DenseMap<llvm::Value *, llvm::Value *> residuals_;
  unsigned budget_ = 32768;
  bool valid_ = true;

  llvm::SmallBitVector empty() const {
    return llvm::SmallBitVector(reductions_.size());
  }
  bool full(const llvm::SmallBitVector &bits) const { return bits.all(); }

  // An unsupported consumer may observe only a complete aggregate. Its
  // operands are replaced, but its own opcode/flags/effects stay untouched.
  llvm::SmallBitVector opaque(llvm::Instruction *instruction, unsigned depth) {
    for (auto &operand: instruction->operands()) {
      auto bits = form(operand.get(), depth + 1);
      if (bits.none())
        continue;
      if (!full(bits)) {
        valid_ = false;
        break;
      }
      boundaries_.insert(operand.get());
    }
    return empty();
  }

  llvm::SmallBitVector form(llvm::Value *value, unsigned depth = 0) {
    if (auto found = forms_.find(value); found != forms_.end())
      return found->second;
    if (!affected_.contains(value))
      return empty();
    if (!budget_ || depth > 256 || !visiting_.insert(value).second) {
      valid_ = false;
      return empty();
    }
    --budget_;
    auto *instruction = llvm::cast<llvm::Instruction>(value);
    auto bits = empty();
    if (wrappingAdd(instruction) &&
        instruction->getType() == reductions_.front().phi->getType()) {
      auto left = form(instruction->getOperand(0), depth + 1);
      auto right = form(instruction->getOperand(1), depth + 1);
      auto overlap = left;
      overlap &= right;
      if (overlap.none()) {
        bits = left;
        bits |= right;
      } else {
        bits = opaque(instruction, depth);
      }
    } else if (auto *select = llvm::dyn_cast<llvm::SelectInst>(instruction);
               select &&
               select->getType() == reductions_.front().phi->getType() &&
               !select->hasMetadataOtherThanDebugLoc()) {
      auto condition = form(select->getCondition(), depth + 1);
      auto left = form(select->getTrueValue(), depth + 1);
      auto right = form(select->getFalseValue(), depth + 1);
      if (condition.none() && left == right)
        bits = left;
      else
        bits = opaque(instruction, depth);
    } else {
      bits = opaque(instruction, depth);
    }
    visiting_.erase(value);
    forms_[value] = bits;
    return bits;
  }

  llvm::Value *residual(llvm::Value *value) {
    if (auto found = residuals_.find(value); found != residuals_.end())
      return found->second;
    auto found = forms_.find(value);
    if (found == forms_.end() || found->second.none())
      return value;
    auto *instruction = llvm::cast<llvm::Instruction>(value);
    // Materialize children first: keep the insertion order correct when a
    // residual folds to a child or is shared by several boundary observations.
    llvm::Value *result;
    if (auto *select = llvm::dyn_cast<llvm::SelectInst>(instruction)) {
      auto *left = residual(select->getTrueValue());
      auto *right = residual(select->getFalseValue());
      llvm::IRBuilder<> builder(instruction);
      result = builder.CreateSelect(select->getCondition(), left, right,
                                    "reduction.residual");
    } else {
      auto *left = residual(instruction->getOperand(0));
      auto *right = residual(instruction->getOperand(1));
      llvm::IRBuilder<> builder(instruction);
      result = builder.CreateAdd(left, right, "reduction.residual");
    }
    residuals_[value] = result;
    return result;
  }

  public:
  AddReduction(llvm::Loop &loop, llvm::SmallVector<Reduction, 8> reductions) :
      loop_(loop), reductions_(std::move(reductions)) {}

  bool analyze() {
    llvm::SmallVector<llvm::Value *, 32> work;
    for (unsigned index = 0; index < reductions_.size(); ++index) {
      auto &reduction = reductions_[index];
      auto bits = empty();
      bits.set(index);
      forms_[reduction.phi] = bits;
      work.push_back(reduction.phi);
    }
    llvm::SmallPtrSet<llvm::Value *, 16> updates;
    for (const auto &reduction: reductions_)
      updates.insert(reduction.update);
    while (!work.empty()) {
      auto *value = work.pop_back_val();
      for (auto *user: value->users()) {
        if (updates.contains(user))
          continue;
        auto *instruction = llvm::dyn_cast<llvm::Instruction>(user);
        if (!instruction || loop_.contains(instruction->getParent()))
          return false;
        if (affected_.insert(instruction).second) {
          if (affected_.size() > 4096)
            return false;
          work.push_back(instruction);
        }
      }
    }
    for (auto *value: affected_) {
      form(value);
      if (!valid_)
        return false;
    }
    return !boundaries_.empty();
  }

  void rewrite() {
    auto *header = loop_.getHeader();
    auto *entry = loop_.getLoopPreheader();
    auto *latch = loop_.getLoopLatch();
    llvm::IRBuilder<> seedBuilder(entry->getTerminator());
    llvm::IRBuilder<> stepBuilder(latch->getTerminator());
    auto *type = reductions_.front().phi->getType();
    auto *zero = llvm::ConstantInt::get(type, 0);
    llvm::Value *seed = zero, *delta = zero;
    llvm::SmallVector<llvm::Metadata *, 8> certificate;
    certificate.push_back(llvm::MDString::get(header->getContext(), "add"));
    for (const auto &reduction: reductions_) {
      seed = seedBuilder.CreateAdd(seed, reduction.seed, "reduction.seed");
      delta = stepBuilder.CreateAdd(delta, reduction.delta, "reduction.delta");
      certificate.push_back(llvm::MDString::get(header->getContext(),
                                                reduction.phi->getName()));
      residuals_[reduction.phi] = zero;
    }
    auto *aggregate = llvm::PHINode::Create(type, 2, "dragon.add.reduction",
                                            header->begin());
    aggregate->addIncoming(seed, entry);
    aggregate->addIncoming(
            stepBuilder.CreateAdd(aggregate, delta, "reduction.next"), latch);
    // This is a proposed state embedding, not a proof. Independent consumers
    // must prove seeds, parallel updates, guard and all observations against
    // the original state model. Never trust metadata as semantic evidence.
    aggregate->setMetadata(
            "dragon.reduction",
            llvm::MDNode::get(header->getContext(), certificate));
    llvm::SmallVector<std::pair<llvm::Value *, llvm::Value *>, 8> replacements;
    for (auto *value: boundaries_) {
      auto *remainder = residual(value);
      llvm::IRBuilder<> builder(llvm::cast<llvm::Instruction>(value));
      replacements.emplace_back(value, builder.CreateAdd(aggregate, remainder,
                                                         "reduction.observed"));
    }
    llvm::SmallVector<llvm::WeakTrackingVH, 8> dead;
    for (const auto &[original, replacement]: replacements) {
      original->replaceAllUsesWith(replacement);
      dead.emplace_back(original);
    }
    for (auto &value: dead)
      if (value)
        llvm::RecursivelyDeleteTriviallyDeadInstructions(value);
    for (const auto &reduction: reductions_)
      llvm::RecursivelyDeleteDeadPHINode(reduction.phi);
  }
};

bool coalesce(llvm::Loop &loop) {
  // A conservative pure, single-latch shape. In particular every recurrence
  // update executes on every taken backedge; no conditional lane updates.
  if (!loop.getSubLoops().empty() || loop.getNumBlocks() != 2 ||
      !loop.getLoopPreheader() || !loop.getLoopLatch())
    return false;
  auto *header = loop.getHeader();
  auto *latch = loop.getLoopLatch();
  auto *branch = llvm::dyn_cast<llvm::BranchInst>(header->getTerminator());
  auto *backedge = llvm::dyn_cast<llvm::BranchInst>(latch->getTerminator());
  if (!branch || !branch->isConditional() || !backedge ||
      !backedge->isUnconditional() || backedge->getSuccessor(0) != header)
    return false;
  llvm::DenseMap<llvm::Type *, llvm::SmallVector<Reduction, 8>> groups;
  for (auto &phi: header->phis()) {
    if (!phi.getType()->isIntegerTy() || !phi.hasName() ||
        phi.getNumIncomingValues() != 2 || phi.hasMetadataOtherThanDebugLoc())
      continue;
    auto *update = llvm::dyn_cast<llvm::BinaryOperator>(
            phi.getIncomingValueForBlock(latch));
    if (!update || !wrappingAdd(update) || !update->hasOneUse() ||
        *update->user_begin() != &phi)
      continue;
    llvm::Value *delta = nullptr;
    if (update->getOperand(0) == &phi && update->getOperand(1) != &phi)
      delta = update->getOperand(1);
    else if (update->getOperand(1) == &phi && update->getOperand(0) != &phi)
      delta = update->getOperand(0);
    if (!delta)
      continue;
    bool independent = true;
    for (auto *user: phi.users())
      if (auto *instruction = llvm::dyn_cast<llvm::Instruction>(user);
          !instruction ||
          (loop.contains(instruction->getParent()) && instruction != update))
        independent = false;
    if (independent)
      groups[phi.getType()].push_back(
              {&phi, update,
               phi.getIncomingValueForBlock(loop.getLoopPreheader()), delta});
  }
  bool changed = false;
  for (auto &[type, reductions]: groups)
    if (reductions.size() >= 2 && reductions.size() <= 64) {
      AddReduction reduction(loop, std::move(reductions));
      if (reduction.analyze()) {
        reduction.rewrite();
        changed = true;
      }
    }
  return changed;
}

class CoalesceAddReductionsPass
    : public llvm::PassInfoMixin<CoalesceAddReductionsPass> {
  public:
  llvm::PreservedAnalyses run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &manager) {
    auto &loops = manager.getResult<llvm::LoopAnalysis>(function);
    bool changed = false;
    for (auto *loop: loops.getLoopsInPreorder())
      changed |= coalesce(*loop);
    return changed ? llvm::PreservedAnalyses::none()
                   : llvm::PreservedAnalyses::all();
  }
};
} // namespace

void dragon::llvmlifter::registerLoopReductionPass(llvm::PassBuilder &builder) {
  builder.registerPipelineParsingCallback(
          [](llvm::StringRef name, llvm::FunctionPassManager &passes,
             llvm::ArrayRef<llvm::PassBuilder::PipelineElement> inner) {
            if (name != "dragon-coalesce-add-reductions" || !inner.empty())
              return false;
            passes.addPass(CoalesceAddReductionsPass());
            return true;
          });
}
