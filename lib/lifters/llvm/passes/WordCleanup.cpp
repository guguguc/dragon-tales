#include "Passes.hpp"

#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/KnownBits.h>

namespace {
using namespace llvm;

// Compare low bits without expanding a modular word into individual lanes.
// Only identities that commute with truncation are traversed. Do not ignore
// poison-generating flags on independently computed values: equal low bits
// alone would not justify making an unselected poisoned rotate observable.
bool sameLowBits(Value *a, Value *b, unsigned bits, unsigned fuel = 12,
                 bool poisonAlreadyObserved = false) {
  if (a == b)
    return true;
  if (!fuel || !a->getType()->isIntegerTy() || !b->getType()->isIntegerTy())
    return false;
  const auto strip = [bits, poisonAlreadyObserved](Value *value) {
    while (auto *cast = dyn_cast<CastInst>(value)) {
      if ((!poisonAlreadyObserved && cast->hasPoisonGeneratingFlags()) ||
          (cast->getOpcode() != Instruction::Trunc &&
           cast->getOpcode() != Instruction::ZExt &&
           cast->getOpcode() != Instruction::SExt) ||
          !cast->getOperand(0)->getType()->isIntegerTy() ||
          cast->getOperand(0)->getType()->getIntegerBitWidth() < bits)
        break;
      value = cast->getOperand(0);
    }
    return value;
  };
  a = strip(a);
  b = strip(b);
  if (a == b)
    return true;
  if (auto *ca = dyn_cast<ConstantInt>(a))
    if (auto *cb = dyn_cast<ConstantInt>(b))
      return ca->getValue().zextOrTrunc(bits) ==
             cb->getValue().zextOrTrunc(bits);
  auto *aa = dyn_cast<BinaryOperator>(a), *bb = dyn_cast<BinaryOperator>(b);
  // Low-bit identity masks are common after register-width normalization.
  for (unsigned swapped = 0; swapped < 2; ++swapped) {
    auto *op = swapped ? bb : aa;
    auto *other = swapped ? a : b;
    if (!op || (!poisonAlreadyObserved && op->hasPoisonGeneratingFlags()))
      continue;
    for (unsigned index = 0; index < 2; ++index)
      if (auto *constant = dyn_cast<ConstantInt>(op->getOperand(index))) {
        const auto low = constant->getValue().zextOrTrunc(bits);
        if ((op->getOpcode() == Instruction::And && low.isAllOnes()) ||
            ((op->getOpcode() == Instruction::Or ||
              op->getOpcode() == Instruction::Xor ||
              op->getOpcode() == Instruction::Add) &&
             low.isZero()))
          if (sameLowBits(op->getOperand(1 - index), other, bits, fuel - 1,
                          poisonAlreadyObserved))
            return true;
      }
  }
  if (!aa || !bb ||
      (!poisonAlreadyObserved &&
       (aa->hasPoisonGeneratingFlags() || bb->hasPoisonGeneratingFlags())) ||
      aa->getOpcode() != bb->getOpcode())
    return false;
  if (aa->getOpcode() == Instruction::Shl) {
    auto *ca = dyn_cast<ConstantInt>(aa->getOperand(1));
    auto *cb = dyn_cast<ConstantInt>(bb->getOperand(1));
    if (!ca || !cb ||
        ca->getValue().getLimitedValue() != cb->getValue().getLimitedValue())
      return false;
    const auto shift = ca->getValue().getLimitedValue();
    if (shift >= aa->getType()->getIntegerBitWidth() ||
        shift >= bb->getType()->getIntegerBitWidth())
      return false;
    return shift >= bits ||
           sameLowBits(aa->getOperand(0), bb->getOperand(0), bits - shift,
                       fuel - 1, poisonAlreadyObserved);
  }
  switch (aa->getOpcode()) {
    case Instruction::Add:
    case Instruction::Sub:
    case Instruction::Mul:
    case Instruction::And:
    case Instruction::Or:
    case Instruction::Xor:
      break;
    default:
      return false;
  }
  return (sameLowBits(aa->getOperand(0), bb->getOperand(0), bits, fuel - 1,
                      poisonAlreadyObserved) &&
          sameLowBits(aa->getOperand(1), bb->getOperand(1), bits, fuel - 1,
                      poisonAlreadyObserved)) ||
         (aa->isCommutative() &&
          sameLowBits(aa->getOperand(0), bb->getOperand(1), bits, fuel - 1,
                      poisonAlreadyObserved) &&
          sameLowBits(aa->getOperand(1), bb->getOperand(0), bits, fuel - 1,
                      poisonAlreadyObserved));
}

// A partial XOR update does not require splitting and reassembling the word:
// ((X ^ Y) & M) | (X & ~M) == X ^ (Y & M). The same X is already observed
// on both sides; replacing the disjoint merge introduces no new poison source.
Value *maskedXorMerge(BinaryOperator &joined) {
  if (joined.getOpcode() != Instruction::Or || !joined.getType()->isIntegerTy())
    return nullptr;
  for (unsigned side = 0; side < 2; ++side) {
    auto *changed = dyn_cast<BinaryOperator>(joined.getOperand(side));
    auto *preserved = dyn_cast<BinaryOperator>(joined.getOperand(1 - side));
    if (!changed || !preserved || changed->getOpcode() != Instruction::And ||
        preserved->getOpcode() != Instruction::And)
      continue;
    auto *mask = dyn_cast<ConstantInt>(changed->getOperand(1));
    auto *other = dyn_cast<ConstantInt>(preserved->getOperand(1));
    auto *differenceValue = changed->getOperand(0);
    if (auto *trunc = dyn_cast<TruncInst>(differenceValue))
      differenceValue = trunc->getOperand(0); // XOR commutes with truncation.
    auto *difference = dyn_cast<BinaryOperator>(differenceValue);
    if (!mask || !other || mask->getValue() != ~other->getValue() ||
        !difference || difference->getOpcode() != Instruction::Xor)
      continue;
    const auto bits = joined.getType()->getIntegerBitWidth();
    for (unsigned input = 0; input < 2; ++input) {
      auto *source = difference->getOperand(input);
      if (!sameLowBits(source, preserved->getOperand(0), bits, 12, true))
        continue;
      IRBuilder<> builder(&joined);
      auto *delta = builder.CreateTruncOrBitCast(difference->getOperand(1 - input), joined.getType());
      return builder.CreateXor(preserved->getOperand(0), builder.CreateAnd(delta, mask));
    }
  }
  return nullptr;
}

// fshl(A,B,k) observes only the low W-k bits of A; fshr(A,B,k)
// observes only its low k bits. Register fragments often compute those bits
// independently at a narrow width even though B already has the full word.
// Reusing B introduces no new poison: B is ALREADY observed by this call.
// In this context modular comparison may ignore poison-generating flags;
// wherever the old funnel was defined, the replacement is equal and defined.
// rotateSelect, in contrast, must keep the stricter default comparisons.
bool canonicalizeFunnel(IntrinsicInst &funnel) {
  const auto id = funnel.getIntrinsicID();
  if ((id != Intrinsic::fshl && id != Intrinsic::fshr) ||
      !funnel.getType()->isIntegerTy())
    return false;
  auto *a = funnel.getArgOperand(0), *b = funnel.getArgOperand(1);
  auto *count = dyn_cast<ConstantInt>(funnel.getArgOperand(2));
  if (a == b || !count)
    return false;
  const auto width = funnel.getType()->getIntegerBitWidth();
  const auto shift = count->getValue().urem(width);
  if (!shift)
    return false;
  const auto bits = id == Intrinsic::fshl ? width - shift : shift;
  if (sameLowBits(a, b, bits, 24, true)) {
    funnel.setArgOperand(0, b);
    return true;
  }
  // A contributes precisely the low `bits` bits. If those are a truncated
  // copy of B with a narrow XOR delta, restore the full source word. Extending
  // the delta by zeros also preserves the complementary bits taken from B.
  auto *extension = dyn_cast<ZExtInst>(a);
  auto *difference = extension ? dyn_cast<BinaryOperator>(extension->getOperand(0)) : nullptr;
  if (!difference || difference->getOpcode() != Instruction::Xor ||
      difference->getType()->getIntegerBitWidth() != bits)
    return false;
  for (unsigned side = 0; side < 2; ++side) {
    if (!sameLowBits(difference->getOperand(side), b, bits, 24, true))
      continue;
    IRBuilder<> builder(&funnel);
    auto *delta = builder.CreateZExt(difference->getOperand(1 - side), b->getType());
    auto *word = builder.CreateXor(b, delta);
    funnel.setArgOperand(0, word);
    funnel.setArgOperand(1, word);
    return true;
  }
  return false;
}

Value *signExtension(BinaryOperator &joined) {
  if (joined.getOpcode() != Instruction::Or || !joined.getType()->isIntegerTy())
    return nullptr;
  const auto width = joined.getType()->getIntegerBitWidth();
  for (unsigned index = 0; index < 2; ++index) {
    auto *mask = dyn_cast<SelectInst>(joined.getOperand(index));
    if (!mask)
      continue;
    auto *compare = dyn_cast<ICmpInst>(mask->getCondition());
    auto *yes = dyn_cast<ConstantInt>(mask->getTrueValue());
    auto *no = dyn_cast<ConstantInt>(mask->getFalseValue());
    if (!compare || !yes || !no)
      continue;
    auto *zero = dyn_cast<ConstantInt>(compare->getOperand(1));
    auto *sign = compare->getOperand(0);
    if (!zero || !zero->isZero() || !sign->getType()->isIntegerTy())
      continue;
    auto bits = sign->getType()->getIntegerBitWidth();
    if (bits >= width)
      continue;
    const auto high = APInt::getHighBitsSet(width, width - bits);
    const auto predicate = compare->getPredicate();
    if (!((predicate == ICmpInst::ICMP_SLT && yes->getValue() == high &&
           no->isZero()) ||
          (predicate == ICmpInst::ICMP_SGE && no->getValue() == high &&
           yes->isZero())))
      continue;
    auto *low = joined.getOperand(1 - index);
    if (!MaskedValueIsZero(low, high, joined.getModule()->getDataLayout()) ||
        !sameLowBits(low, sign, bits))
      continue;
    IRBuilder<> builder(&joined);
    return builder.CreateSExt(sign, joined.getType());
  }
  return nullptr;
}

// zext((trunc(A) op C) & M) can stay in A's word width: the mask
// observes only the original narrow bits. This avoids trunc/add/mask/zext
// chains in shift counts without changing arbitrary unmasked extensions.
Value *maskedWordArithmetic(CastInst &cast) {
  if (cast.getOpcode() != Instruction::ZExt || !cast.getType()->isIntegerTy())
    return nullptr;
  auto *masked = dyn_cast<BinaryOperator>(cast.getOperand(0));
  if (!masked || masked->getOpcode() != Instruction::And)
    return nullptr;
  auto *mask = dyn_cast<ConstantInt>(masked->getOperand(1));
  auto *operation = dyn_cast<BinaryOperator>(masked->getOperand(0));
  if (!mask || !operation)
    return nullptr;
  switch (operation->getOpcode()) {
    case Instruction::Add:
    case Instruction::Sub:
    case Instruction::Mul:
    case Instruction::Xor:
    case Instruction::Or:
    case Instruction::And:
      break;
    default:
      return nullptr;
  }
  Value *wide[2]{};
  for (unsigned i = 0; i < 2; ++i) {
    auto *value = operation->getOperand(i);
    if (auto *constant = dyn_cast<ConstantInt>(value))
      wide[i] = ConstantInt::get(cast.getType(), constant->getValue().zext(
              cast.getType()->getIntegerBitWidth()));
    else if (auto *trunc = dyn_cast<TruncInst>(value))
      if (trunc->getOperand(0)->getType() == cast.getType())
        wide[i] = trunc->getOperand(0);
    if (!wide[i])
      return nullptr;
  }
  IRBuilder<> builder(&cast);
  auto *word = builder.CreateBinOp(operation->getOpcode(), wide[0], wide[1]);
  auto *wideMask = ConstantInt::get(cast.getType(), mask->getValue().zext(
          cast.getType()->getIntegerBitWidth()));
  return builder.CreateAnd(word, wideMask);
}

// Drop width-preserving low-bit wrappers when recognizing a modular negation.
Value *countCore(Value *value, unsigned bits) {
  for (;;) {
    if (auto *cast = dyn_cast<CastInst>(value)) {
      if (cast->hasPoisonGeneratingFlags() ||
          (cast->getOpcode() != Instruction::Trunc &&
           cast->getOpcode() != Instruction::ZExt &&
           cast->getOpcode() != Instruction::SExt) ||
          !cast->getOperand(0)->getType()->isIntegerTy() ||
          cast->getOperand(0)->getType()->getIntegerBitWidth() < bits)
        return value;
      value = cast->getOperand(0);
      continue;
    }
    auto *op = dyn_cast<BinaryOperator>(value);
    if (!op || op->getOpcode() != Instruction::And)
      return value;
    Value *unmasked = nullptr;
    for (unsigned i = 0; i < 2; ++i)
      if (auto *mask = dyn_cast<ConstantInt>(op->getOperand(i)))
        if (mask->getValue().zextOrTrunc(bits).isAllOnes()) {
          unmasked = op->getOperand(1 - i);
          break;
        }
    if (!unmasked)
      return value;
    value = unmasked;
  }
}

Value *modularRotate(BinaryOperator &joined) {
  if (joined.getOpcode() != Instruction::Or || !joined.getType()->isIntegerTy())
    return nullptr;
  const auto width = joined.getType()->getIntegerBitWidth();
  if (width < 2 || !isPowerOf2_32(width))
    return nullptr;
  auto *left = dyn_cast<BinaryOperator>(joined.getOperand(0));
  auto *right = dyn_cast<BinaryOperator>(joined.getOperand(1));
  if (left && left->getOpcode() == Instruction::LShr)
    std::swap(left, right);
  if (!left || !right || left->getOpcode() != Instruction::Shl ||
      right->getOpcode() != Instruction::LShr ||
      left->getOperand(0) != right->getOperand(0))
    return nullptr;
  auto *a = left->getOperand(1), *b = right->getOperand(1);
  const auto &layout = joined.getModule()->getDataLayout();
  if (!computeKnownBits(a, layout).getMaxValue().ult(width) ||
      !computeKnownBits(b, layout).getMaxValue().ult(width))
    return nullptr;
  const auto bits = Log2_32(width);
  const auto negates = [bits](Value *negative, Value *positive) {
    auto *op = dyn_cast<BinaryOperator>(countCore(negative, bits));
    if (!op || op->getOpcode() != Instruction::Sub ||
        op->hasPoisonGeneratingFlags())
      return false;
    auto *zero = dyn_cast<ConstantInt>(op->getOperand(0));
    return zero && zero->isZero() &&
           sameLowBits(op->getOperand(1), positive, bits);
  };
  if (!negates(a, b) && !negates(b, a))
    return nullptr;
  IRBuilder<> builder(&joined);
  auto *word = left->getOperand(0);
  return builder.CreateIntrinsic(Intrinsic::fshl, {joined.getType()},
                                 {word, word, a});
}

// A rotate is already total at zero count. Remove the extra machine-level
// zero-count select only when its condition tests the SAME count modulo width.
Value *rotateSelect(SelectInst &select) {
  auto *compare = dyn_cast<ICmpInst>(select.getCondition());
  if (!compare || (compare->getPredicate() != ICmpInst::ICMP_EQ &&
                   compare->getPredicate() != ICmpInst::ICMP_NE))
    return nullptr;
  Value *count = compare->getOperand(0);
  auto *zero = dyn_cast<ConstantInt>(compare->getOperand(1));
  if (!zero || !zero->isZero())
    return nullptr;
  const bool equal = compare->getPredicate() == ICmpInst::ICMP_EQ;
  auto *plain = equal ? select.getTrueValue() : select.getFalseValue();
  auto *funnel = dyn_cast<IntrinsicInst>(equal ? select.getFalseValue()
                                               : select.getTrueValue());
  if (!funnel ||
      (funnel->getIntrinsicID() != Intrinsic::fshl &&
       funnel->getIntrinsicID() != Intrinsic::fshr) ||
      funnel->getArgOperand(0) != plain || funnel->getArgOperand(1) != plain ||
      !plain->getType()->isIntegerTy())
    return nullptr;
  const auto width = plain->getType()->getIntegerBitWidth();
  if (!isPowerOf2_32(width))
    return nullptr;
  // Truncated counts may omit bits only above log2(width). An explicit AND
  // must be exactly width-1; arbitrary zero tests do not imply zero rotation.
  const auto bits = Log2_32(width);
  if (!bits)
    return plain;
  if (auto *op = dyn_cast<BinaryOperator>(count)) {
    if (op->getOpcode() != Instruction::And)
      return nullptr;
    auto *mask = dyn_cast<ConstantInt>(op->getOperand(1));
    if (!mask || mask->getValue() != width - 1)
      return nullptr;
    count = op->getOperand(0);
  } else if (count->getType()->getIntegerBitWidth() != bits) {
    return nullptr;
  }
  return sameLowBits(count, funnel->getArgOperand(2), bits) ? funnel : nullptr;
}

class WordCleanupPass : public PassInfoMixin<WordCleanupPass> {
  public:
  PreservedAnalyses run(Function &function, FunctionAnalysisManager &) {
    bool changed = false;
    for (auto &block: function)
      for (auto iterator = block.begin(); iterator != block.end();) {
        auto &instruction = *iterator++;
        Value *replacement = nullptr;
        if (auto *funnel = dyn_cast<IntrinsicInst>(&instruction))
          changed |= canonicalizeFunnel(*funnel);
        if (auto *joined = dyn_cast<BinaryOperator>(&instruction)) {
          replacement = maskedXorMerge(*joined);
          if (!replacement)
            replacement = modularRotate(*joined);
          if (!replacement)
            replacement = signExtension(*joined);
        }
        if (auto *cast = dyn_cast<CastInst>(&instruction))
          replacement = maskedWordArithmetic(*cast);
        if (auto *select = dyn_cast<SelectInst>(&instruction))
          replacement = rotateSelect(*select);
        if (replacement) {
          instruction.replaceAllUsesWith(replacement);
          instruction.eraseFromParent();
          changed = true;
        }
      }
    return changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
  }
};
} // namespace

void dragon::llvmlifter::registerWordCleanupPass(llvm::PassBuilder &builder) {
  builder.registerPipelineParsingCallback(
          [](llvm::StringRef name, llvm::FunctionPassManager &passes,
             llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
            if (name != "dragon-clean-words")
              return false;
            passes.addPass(WordCleanupPass());
            return true;
          });
}
