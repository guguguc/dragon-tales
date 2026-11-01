#include "Passes.hpp"

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallBitVector.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Analysis/ValueTracking.h>
#include <llvm/IR/ConstantRange.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/ValueHandle.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/KnownBits.h>
#include <llvm/Transforms/Utils/Local.h>

#include <algorithm>
#include <bit>
#include <cstdlib>
#include <map>
#include <memory>
#include <numeric>
#include <optional>
#include <tuple>
#include <vector>

namespace {
// Bounded exact polynomial normalization in Z/(2^width). Narrow operations,
// extensions, select, memory, freeze and unsupported opcodes remain atoms.
// There are no recognized source algorithms or sample-specific constants.
using Monomial = std::vector<unsigned>;
using Polynomial = std::map<Monomial, llvm::APInt>;

class ModularPolynomial {
  llvm::Function &function_;
  llvm::DominatorTree dominators_;
  llvm::DenseMap<llvm::Value *, unsigned> atomIDs_;
  llvm::SmallVector<llvm::Value *, 32> atoms_;
  llvm::DenseMap<llvm::Value *, Polynomial> memo_;
  llvm::SmallPtrSet<llvm::Instruction *, 32> expanded_;
  unsigned width_ = 0;
  unsigned remaining_ = 65536;
  static constexpr unsigned MaxTerms = 64;
  static constexpr unsigned MaxDegree = 4;

  Polynomial atom(llvm::Value *value) {
    auto [found, inserted] = atomIDs_.try_emplace(value, atoms_.size());
    if (inserted)
      atoms_.push_back(value);
    return {{Monomial{found->second}, llvm::APInt(width_, 1)}};
  }

  void addTerm(Polynomial &result, Monomial monomial, llvm::APInt coefficient) {
    auto found = result.find(monomial);
    if (found != result.end()) {
      coefficient += found->second;
      result.erase(found);
    }
    if (!coefficient.isZero())
      result.emplace(std::move(monomial), std::move(coefficient));
  }

  std::optional<Polynomial> add(Polynomial left, const Polynomial &right,
                                bool subtract = false) {
    for (const auto &[monomial, coefficient]: right)
      addTerm(left, monomial, subtract ? -coefficient : coefficient);
    if (left.size() > MaxTerms)
      return std::nullopt;
    return left;
  }

  std::optional<Polynomial> multiply(const Polynomial &left,
                                     const Polynomial &right) {
    Polynomial result;
    for (const auto &[x, a]: left)
      for (const auto &[y, b]: right) {
        if (!remaining_ || x.size() + y.size() > MaxDegree)
          return std::nullopt;
        --remaining_;
        Monomial product;
        std::merge(x.begin(), x.end(), y.begin(), y.end(),
                   std::back_inserter(product));
        addTerm(result, std::move(product), a * b);
        if (result.size() > MaxTerms)
          return std::nullopt;
      }
    return result;
  }

  bool redundantAddFlags(llvm::BinaryOperator *add) const {
    if (!add->hasNoUnsignedWrap() && !add->hasNoSignedWrap())
      return true;
    // Bounds are conservative and refer to the actual LLVM expression. Flags
    // are removed only if both signed/unsigned extrema prove no overflow.
    auto left = llvm::computeKnownBits(add->getOperand(0),
                                       function_.getDataLayout());
    auto right = llvm::computeKnownBits(add->getOperand(1),
                                        function_.getDataLayout());
    bool overflow;
    if (add->hasNoUnsignedWrap()) {
      (void) left.getMaxValue().uadd_ov(right.getMaxValue(), overflow);
      if (overflow)
        return false;
    }
    if (add->hasNoSignedWrap()) {
      (void) left.getSignedMinValue().sadd_ov(right.getSignedMinValue(),
                                              overflow);
      if (overflow)
        return false;
      (void) left.getSignedMaxValue().sadd_ov(right.getSignedMaxValue(),
                                              overflow);
      if (overflow)
        return false;
    }
    return true;
  }

  std::optional<Polynomial> parse(llvm::Value *value, unsigned depth = 0) {
    if (auto found = memo_.find(value); found != memo_.end())
      return found->second;
    if (!remaining_ || depth > 64)
      return std::nullopt;
    --remaining_;
    if (auto *constant = llvm::dyn_cast<llvm::ConstantInt>(value)) {
      Polynomial result;
      addTerm(result, {}, constant->getValue());
      return result;
    }
    auto *binary = llvm::dyn_cast<llvm::BinaryOperator>(value);
    if (!binary || !value->getType()->isIntegerTy(width_) ||
        binary->hasMetadataOtherThanDebugLoc())
      return atom(value);
    const auto opcode = binary->getOpcode();
    std::optional<Polynomial> result;
    if ((opcode == llvm::Instruction::Add && redundantAddFlags(binary)) ||
        ((opcode == llvm::Instruction::Sub ||
          opcode == llvm::Instruction::Mul) &&
         !binary->hasNoSignedWrap() && !binary->hasNoUnsignedWrap())) {
      auto left = parse(binary->getOperand(0), depth + 1);
      auto right = parse(binary->getOperand(1), depth + 1);
      if (!left || !right)
        return std::nullopt;
      if (opcode == llvm::Instruction::Mul)
        result = multiply(*left, *right);
      else
        result =
                add(std::move(*left), *right, opcode == llvm::Instruction::Sub);
    } else if (opcode == llvm::Instruction::Shl && !binary->hasNoSignedWrap() &&
               !binary->hasNoUnsignedWrap()) {
      auto *amount = llvm::dyn_cast<llvm::ConstantInt>(binary->getOperand(1));
      if (!amount || amount->getValue().uge(width_))
        return atom(value);
      auto left = parse(binary->getOperand(0), depth + 1);
      if (!left)
        return std::nullopt;
      Polynomial scale{
              {{}, llvm::APInt::getOneBitSet(width_, amount->getZExtValue())}};
      result = multiply(*left, scale);
    } else if (opcode == llvm::Instruction::And ||
               opcode == llvm::Instruction::Or ||
               opcode == llvm::Instruction::Xor) {
      auto *source = binary->getOperand(0);
      auto *mask = llvm::dyn_cast<llvm::ConstantInt>(binary->getOperand(1));
      if (!mask) {
        source = binary->getOperand(1);
        mask = llvm::dyn_cast<llvm::ConstantInt>(binary->getOperand(0));
      }
      if (mask) {
        auto known = llvm::computeKnownBits(source, function_.getDataLayout());
        const auto relevant = opcode == llvm::Instruction::And
                                      ? ~mask->getValue()
                                      : mask->getValue();
        const auto *disjoint =
                llvm::dyn_cast<llvm::PossiblyDisjointInst>(binary);
        const bool flagsSafe = !disjoint || !disjoint->isDisjoint() ||
                               (mask->getValue() & ~known.Zero).isZero();
        if (flagsSafe && (relevant & ~(known.One | known.Zero)).isZero()) {
          // Known-bit toggles have an exact modular arithmetic translation.
          // Unknown cleared/set/toggled bits remain opaque, as do nonredundant
          // disjoint flags. This is not distribution across a narrow overflow.
          auto sourcePolynomial = parse(source, depth + 1);
          if (!sourcePolynomial)
            return std::nullopt;
          result = std::move(*sourcePolynomial);
          auto offset = llvm::APInt(width_, 0);
          if (opcode != llvm::Instruction::And)
            offset += known.Zero & relevant;
          if (opcode != llvm::Instruction::Or)
            offset -= known.One & relevant;
          addTerm(*result, {}, std::move(offset));
        }
      }
      if (!result)
        return atom(value);
    } else {
      return atom(value);
    }
    if (!result)
      return std::nullopt;
    expanded_.insert(binary);
    memo_[value] = *result;
    return result;
  }

  unsigned deadCost(llvm::Instruction *root) const {
    llvm::SmallPtrSet<llvm::Instruction *, 32> dead;
    dead.insert(root);
    bool changed = true;
    while (changed) {
      changed = false;
      for (auto *instruction: expanded_) {
        if (dead.contains(instruction))
          continue;
        if (llvm::all_of(instruction->users(), [&](llvm::User *user) {
              return dead.contains(llvm::dyn_cast<llvm::Instruction>(user));
            })) {
          dead.insert(instruction);
          changed = true;
        }
      }
    }
    return dead.size();
  }

  struct SelectCase {
    llvm::Value *selector;
    llvm::ConstantInt *literal;
    llvm::CmpInst::Predicate predicate;
  };

  std::optional<SelectCase> selectorCase(llvm::SelectInst *select) const {
    if (select->hasMetadataOtherThanDebugLoc())
      return std::nullopt;
    auto *compare = llvm::dyn_cast<llvm::ICmpInst>(select->getCondition());
    if (!compare || (!compare->isEquality() && !compare->isSigned()) ||
        compare->hasSameSign() || compare->hasMetadataOtherThanDebugLoc())
      return std::nullopt;
    auto predicate = compare->getPredicate();
    auto *selector = compare->getOperand(0);
    auto *literal = llvm::dyn_cast<llvm::ConstantInt>(compare->getOperand(1));
    if (!literal) {
      selector = compare->getOperand(1);
      literal = llvm::dyn_cast<llvm::ConstantInt>(compare->getOperand(0));
      predicate = llvm::CmpInst::getSwappedPredicate(predicate);
    }
    if (!literal || !selector->getType()->isIntegerTy() ||
        selector->getType()->getIntegerBitWidth() > 256)
      return std::nullopt;
    return SelectCase{selector, literal, predicate};
  }

  // Visit the actual decision DAG. An exhaustive small LLVM integer domain,
  // not a set of captured input values, determines every table row.
  bool gather(llvm::Value *value, llvm::Value *selector,
              llvm::SmallPtrSetImpl<llvm::Value *> &seen, unsigned depth = 0) {
    if (!remaining_ || depth > 64)
      return false;
    --remaining_;
    auto *select = llvm::dyn_cast<llvm::SelectInst>(value);
    if (!select || !seen.insert(select).second)
      return true;
    const auto test = selectorCase(select);
    if (!test || test->selector != selector)
      return false;
    expanded_.insert(select);
    expanded_.insert(llvm::cast<llvm::Instruction>(select->getCondition()));
    return gather(select->getTrueValue(), selector, seen, depth + 1) &&
           gather(select->getFalseValue(), selector, seen, depth + 1);
  }

  llvm::Value *leaf(llvm::Value *value, const llvm::APInt &index) const {
    while (auto *select = llvm::dyn_cast<llvm::SelectInst>(value)) {
      const auto test = *selectorCase(select); // gather validated the whole DAG
      value = llvm::ICmpInst::compare(index, test.literal->getValue(),
                                      test.predicate)
                      ? select->getTrueValue()
                      : select->getFalseValue();
    }
    return value;
  }

  struct SelectDomain {
    llvm::APInt first, last;
    bool clampLow = false, clampHigh = false;
    unsigned count() const { return (last - first).getZExtValue() + 1; }
  };

  std::optional<SelectDomain>
  selectDomain(llvm::SelectInst *root, llvm::Value *selector,
               const llvm::SmallPtrSetImpl<llvm::Value *> &seen) const {
    const unsigned bits = selector->getType()->getIntegerBitWidth();
    if (bits <= 4)
      return SelectDomain{llvm::APInt(bits, 0), llvm::APInt::getMaxValue(bits)};
    llvm::ConstantRange range(bits, true);
    // Only actual dominating CFG edges restrict the table. Captured inputs,
    // guessed source types and the current executor path never do.
    auto *block = root->getParent();
    for (auto *node = dominators_.getNode(block); node;
         node = node->getIDom()) {
      auto *branch = llvm::dyn_cast<llvm::BranchInst>(
              node->getBlock()->getTerminator());
      if (!branch || !branch->isConditional())
        continue;
      bool yes = dominators_.dominates(
              llvm::BasicBlockEdge(node->getBlock(), branch->getSuccessor(0)),
              block);
      bool no = dominators_.dominates(
              llvm::BasicBlockEdge(node->getBlock(), branch->getSuccessor(1)),
              block);
      if (yes == no)
        continue;
      auto *cmp = llvm::dyn_cast<llvm::ICmpInst>(branch->getCondition());
      if (!cmp)
        continue;
      auto pred = cmp->getPredicate();
      llvm::ConstantInt *literal = nullptr;
      if (cmp->getOperand(0) == selector)
        literal = llvm::dyn_cast<llvm::ConstantInt>(cmp->getOperand(1));
      else if (cmp->getOperand(1) == selector) {
        literal = llvm::dyn_cast<llvm::ConstantInt>(cmp->getOperand(0));
        pred = llvm::CmpInst::getSwappedPredicate(pred);
      }
      if (literal) {
        if (no)
          pred = llvm::CmpInst::getInversePredicate(pred);
        range = range.intersectWith(llvm::ConstantRange::makeExactICmpRegion(
                pred, literal->getValue()));
      }
    }
    if (range.isEmptySet())
      return std::nullopt;
    auto low = llvm::APInt::getSignedMaxValue(bits);
    auto high = llvm::APInt::getSignedMinValue(bits);
    auto cut = [&](llvm::APInt value) {
      if (value.slt(low))
        low = value;
      if (value.sgt(high))
        high = value;
    };
    for (auto *value: seen) {
      const auto test = *selectorCase(llvm::cast<llvm::SelectInst>(value));
      auto c = test.literal->getValue();
      switch (test.predicate) {
        case llvm::CmpInst::ICMP_EQ:
        case llvm::CmpInst::ICMP_NE:
          cut(c);
          if (!c.isMaxSignedValue())
            cut(c + 1);
          break;
        case llvm::CmpInst::ICMP_SLT:
        case llvm::CmpInst::ICMP_SGE:
          cut(c);
          break;
        default:
          if (!c.isMaxSignedValue())
            cut(c + 1);
          break;
      }
    }
    // The decision is constant below the first cut and after the last cut.
    // Include one representative of each plateau, then clamp only those tails.
    if (!low.isMinSignedValue())
      --low;
    low = llvm::APIntOps::smax(low, range.getSignedMin());
    high = llvm::APIntOps::smin(high, range.getSignedMax());
    if (high.slt(low) || (high - low).getLimitedValue(16) >= 16)
      return std::nullopt;
    return SelectDomain{low, high, range.getSignedMin().slt(low),
                        range.getSignedMax().sgt(high)};
  }

  using Differences = std::map<Monomial, std::vector<llvm::APInt>>;

  std::optional<Differences> differences(const std::vector<Polynomial> &rows) {
    Differences result;
    for (const auto &row: rows)
      for (const auto &[monomial, coefficient]: row)
        result.try_emplace(monomial);
    if (result.size() > MaxTerms)
      return std::nullopt;
    // A new eager polynomial must not observe an opaque poison value that was
    // masked by a select. Every retained atom must occur in EVERY original
    // case's unmasked arithmetic. Unknown/flagged case-only atoms fail closed.
    llvm::SmallVector<llvm::SmallBitVector, 16> used;
    for (const auto &row: rows) {
      llvm::SmallBitVector bits(atoms_.size());
      for (const auto &[monomial, coefficient]: row)
        for (const auto id: monomial)
          bits.set(id);
      used.push_back(std::move(bits));
    }
    for (unsigned i = 1; i < used.size(); ++i)
      if (used[i] != used.front())
        return std::nullopt;
    for (auto &[monomial, delta]: result) {
      std::vector<llvm::APInt> column;
      for (const auto &row: rows) {
        auto found = row.find(monomial);
        column.push_back(found == row.end() ? llvm::APInt(width_, 0)
                                            : found->second);
      }
      for (unsigned order = 0; !column.empty(); ++order) {
        if (!remaining_)
          return std::nullopt;
        --remaining_;
        if (order <= MaxDegree)
          delta.push_back(column.front());
        else if (!column.front().isZero())
          return std::nullopt;
        for (unsigned i = 0; i + 1 < column.size(); ++i)
          column[i] = column[i + 1] - column[i];
        column.pop_back();
      }
      while (!delta.empty() && delta.back().isZero())
        delta.pop_back();
    }
    return result;
  }

  llvm::Value *buildSelect(const Differences &table, llvm::Value *selector,
                           llvm::IntegerType *type, llvm::BasicBlock *scratch,
                           unsigned maximum) {
    unsigned degree = 0;
    for (const auto &[monomial, delta]: table)
      if (!delta.empty())
        degree = std::max(degree, unsigned(delta.size() - 1));
    // Newton's finite-difference identity uses integer-valued binomials.
    // Falling products are computed wide enough BEFORE exact integer division;
    // payload arithmetic stays modulo its original width. No modular inverse
    // of an even factorial, narrow overflow or floating point interpolation.
    unsigned maximumProduct = 1;
    for (unsigned k = 0; k < degree; ++k)
      maximumProduct *= maximum - k;
    const unsigned workWidth =
            std::max(width_, unsigned(std::bit_width(maximumProduct)));
    llvm::IRBuilder<> builder(scratch);
    auto *workType = llvm::IntegerType::get(function_.getContext(), workWidth);
    // LLVM undef may choose a different value at every use. Freeze once so
    // polynomial expansion selects one coherent table row; freezing a poison
    // selector is a permitted refinement of the original poisoned decision.
    auto *chosen = selector;
    auto *index =
            builder.CreateZExtOrTrunc(chosen, workType, "small.select.index");
    llvm::SmallVector<llvm::Value *, 5> falling{
            llvm::ConstantInt::get(workType, 1)};
    for (unsigned k = 1; k <= degree; ++k) {
      auto *factor =
              k == 1 ? index
                     : builder.CreateSub(
                               index, llvm::ConstantInt::get(workType, k - 1),
                               "small.select.factor");
      falling.push_back(k == 1 ? index
                               : builder.CreateMul(falling.back(), factor,
                                                   "small.select.falling"));
    }
    std::map<std::pair<unsigned, unsigned>, llvm::Value *> quotients;
    llvm::DenseMap<unsigned, llvm::Value *> frozenAtoms;
    llvm::Value *result = nullptr;
    for (const auto &[monomial, delta]: table) {
      llvm::Value *coefficient = nullptr;
      unsigned factorial = 1;
      for (unsigned k = 0; k < delta.size(); ++k) {
        factorial *= k ? k : 1;
        if (delta[k].isZero())
          continue;
        auto *term = static_cast<llvm::Value *>(
                llvm::ConstantInt::get(type, delta[k]));
        if (k) {
          const unsigned literalWidth = std::max(16u, width_);
          const auto residue =
                  delta[k].zextOrTrunc(literalWidth)
                          .urem(llvm::APInt(literalWidth, factorial))
                          .getZExtValue();
          const unsigned divisor = std::gcd(factorial, unsigned(residue));
          const unsigned denominator = factorial / divisor;
          auto key = std::make_pair(k, denominator);
          auto found = quotients.find(key);
          llvm::Value *basis;
          if (found != quotients.end())
            basis = found->second;
          else {
            basis = falling[k];
            if (denominator != 1)
              basis = builder.CreateUDiv(
                      basis, llvm::ConstantInt::get(workType, denominator),
                      "small.select.binomial");
            basis = builder.CreateZExtOrTrunc(basis, type,
                                              "small.select.basis");
            quotients[key] = basis;
          }
          auto scaled = divisor == 1
                                ? delta[k]
                                : delta[k].udiv(llvm::APInt(width_, divisor));
          term = scaled.isOne()
                         ? basis
                         : builder.CreateMul(
                                   basis, llvm::ConstantInt::get(type, scaled),
                                   "small.select.coefficient");
        }
        coefficient = coefficient
                              ? builder.CreateAdd(coefficient, term,
                                                  "small.select.coefficients")
                              : term;
      }
      if (!coefficient)
        continue;
      llvm::Value *product = nullptr;
      for (const auto id: monomial) {
        auto [found, inserted] = frozenAtoms.try_emplace(id);
        if (inserted)
          found->second = builder.CreateFreeze(atoms_[id], "small.select.atom");
        product = product ? builder.CreateMul(product, found->second,
                                              "small.select.product")
                          : found->second;
      }
      auto *term = product ? builder.CreateMul(coefficient, product,
                                               "small.select.term")
                           : coefficient;
      result = result ? builder.CreateAdd(result, term, "small.select.sum")
                      : term;
    }
    return result ? result : llvm::ConstantInt::get(type, 0);
  }

  // Factor a sum in the modular ring by shared atoms, not by a recognized
  // algorithm. This also shares linear factors across coefficient columns.
  llvm::Value *factorSum(const Polynomial &terms, llvm::IRBuilder<> &builder,
                         llvm::IntegerType *type,
                         const std::vector<llvm::Value *> &factors) {
    std::map<unsigned, unsigned> counts;
    for (const auto &[monomial, coefficient]: terms) {
      unsigned previous = unsigned(-1);
      for (unsigned id: monomial) {
        if (id != previous)
          ++counts[id];
        previous = id;
      }
    }
    unsigned best = 0, frequency = 1;
    for (auto [id, count]: counts)
      if (count > frequency) {
        best = id;
        frequency = count;
      }
    if (frequency > 1) {
      Polynomial with, without;
      for (const auto &[monomial, coefficient]: terms) {
        auto reduced = monomial;
        auto found = std::find(reduced.begin(), reduced.end(), best);
        if (found == reduced.end())
          addTerm(without, reduced, coefficient);
        else {
          reduced.erase(found);
          addTerm(with, reduced, coefficient);
        }
      }
      auto *product = builder.CreateMul(factors[best],
                                        factorSum(with, builder, type, factors),
                                        "small.select.factored");
      return without.empty() ? product
                             : builder.CreateAdd(product,
                                                 factorSum(without, builder,
                                                           type, factors),
                                                 "small.select.sum");
    }
    llvm::Value *result = nullptr;
    for (const auto &[monomial, coefficient]: terms) {
      llvm::Value *term = coefficient.isOne() && !monomial.empty()
                                  ? nullptr
                                  : llvm::ConstantInt::get(type, coefficient);
      for (unsigned id: monomial)
        term = term ? builder.CreateMul(term, factors[id],
                                        "small.select.product")
                    : factors[id];
      result = result ? builder.CreateAdd(result, term, "small.select.sum")
                      : term;
    }
    return result ? result : llvm::ConstantInt::get(type, 0);
  }

  using PowerPolynomial = std::vector<llvm::APInt>;
  static void trim(PowerPolynomial &p) {
    while (!p.empty() && p.back().isZero())
      p.pop_back();
  }

  // Convert Newton's integer-valued basis to ONE rational power polynomial.
  // Coefficients are lifted signed into extra precision before any division.
  // A modular delta lift changes the result only by 2^width * binomial(x,k).
  std::pair<PowerPolynomial, unsigned>
  powerColumn(const std::vector<llvm::APInt> &delta, bool splitConstant) const {
    const unsigned bits = width_ + 64;
    unsigned denominator = 1;
    for (unsigned k = 1; k < delta.size(); ++k)
      denominator *= k;
    PowerPolynomial result(delta.size(), llvm::APInt(bits, 0));
    PowerPolynomial falling{llvm::APInt(bits, 1)};
    unsigned factorial = 1;
    for (unsigned k = 0; k < delta.size(); ++k) {
      factorial *= k ? k : 1;
      if (k || !splitConstant)
        for (unsigned j = 0; j < falling.size(); ++j)
          result[j] +=
                  falling[j] * delta[k].sext(bits) * (denominator / factorial);
      PowerPolynomial next(falling.size() + 1, llvm::APInt(bits, 0));
      for (unsigned j = 0; j < falling.size(); ++j) {
        next[j + 1] += falling[j];
        next[j] -= falling[j] * k;
      }
      falling = std::move(next);
    }
    unsigned common = denominator;
    for (const auto &coefficient: result)
      common =
              std::gcd(common, unsigned(coefficient.abs()
                                                .urem(llvm::APInt(bits, common))
                                                .getZExtValue()));
    for (auto &coefficient: result)
      coefficient = coefficient.sdiv(llvm::APInt(bits, common));
    trim(result);
    return {std::move(result), denominator / common};
  }

  // Exact synthetic division by a*x+b. Small rational roots are bounded
  // proposals; a missed factor merely leaves a Horner polynomial unchanged.
  std::optional<PowerPolynomial> divideLinear(const PowerPolynomial &p, int a,
                                              int b) {
    if (p.size() < 2 || !remaining_)
      return std::nullopt;
    --remaining_;
    const unsigned bits = p.front().getBitWidth();
    llvm::APInt aa(bits, a), bb(bits, uint64_t(b), true);
    PowerPolynomial q(p.size() - 1, llvm::APInt(bits, 0));
    llvm::APInt carry(bits, 0);
    for (unsigned k = p.size() - 1; k; --k) {
      auto value = p[k] - carry;
      if (!value.srem(aa).isZero())
        return std::nullopt;
      q[k - 1] = value.sdiv(aa);
      carry = q[k - 1] * bb;
    }
    if (carry != p.front())
      return std::nullopt;
    return q;
  }

  llvm::Value *buildFactoredSelect(const Differences &table,
                                   llvm::Value *selector,
                                   llvm::IntegerType *type,
                                   llvm::BasicBlock *scratch,
                                   unsigned maximum) {
    llvm::IRBuilder<> builder(scratch);
    auto *chosen = selector;
    std::vector<llvm::Value *> factors;
    llvm::DenseMap<llvm::Value *, unsigned> ids;
    auto intern = [&](llvm::Value *value) {
      auto [it, inserted] = ids.try_emplace(value, factors.size());
      if (inserted)
        factors.push_back(value);
      return it->second;
    };
    std::map<std::tuple<unsigned, int, int>, llvm::Value *> linearValues;
    std::map<unsigned, llvm::Value *> indices;
    auto linear = [&](int a, int b, llvm::IntegerType *workType) {
      auto key = std::make_tuple(workType->getBitWidth(), a, b);
      auto found = linearValues.find(key);
      if (found != linearValues.end())
        return found->second;
      auto [index, inserted] = indices.try_emplace(workType->getBitWidth());
      if (inserted)
        index->second = builder.CreateZExtOrTrunc(chosen, workType,
                                                  "small.select.index");
      auto *value = index->second;
      if (a != 1)
        value = builder.CreateMul(value, llvm::ConstantInt::get(workType, a),
                                  "small.select.scale");
      if (b)
        value = builder.CreateAdd(value,
                                  llvm::ConstantInt::getSigned(workType, b),
                                  "small.select.factor");
      linearValues[key] = value;
      return value;
    };
    Polynomial terms;
    llvm::DenseMap<unsigned, unsigned> frozenAtoms;
    for (const auto &[monomial, delta]: table) {
      if (delta.empty())
        continue;
      const bool splitConstant = monomial.empty();
      if (splitConstant)
        addTerm(terms, {}, delta.front());
      auto [p, denominator] = powerColumn(delta, splitConstant);
      if (p.empty())
        continue;
      const unsigned bits = p.front().getBitWidth();
      // An absolute coefficient bound proves the exact numerator cannot wrap,
      // even before cancellation. Division happens before payload truncation.
      llvm::APInt bound(bits, 0), power(bits, 1);
      for (const auto &coefficient: p) {
        bound += coefficient.abs() * power;
        power *= maximum;
      }
      bool nonnegative = true;
      for (unsigned x = 0; x <= maximum; ++x) {
        llvm::APInt numerator(bits, 0);
        for (auto it = p.rbegin(); it != p.rend(); ++it)
          numerator = numerator * x + *it;
        nonnegative &= !numerator.isNegative();
      }
      const unsigned workWidth =
              denominator == 1 ? width_
                               : std::max(width_, bound.getActiveBits() + 1);
      auto *workType =
              llvm::IntegerType::get(function_.getContext(), workWidth);
      llvm::APInt content(bits, 0);
      for (const auto &coefficient: p) {
        auto c = coefficient.abs();
        while (!c.isZero()) {
          auto r = content.urem(c);
          content = c;
          c = std::move(r);
        }
      }
      if (p.back().isNegative())
        content.negate();
      for (auto &coefficient: p)
        coefficient = coefficient.sdiv(content);
      std::vector<std::pair<int, int>> roots;
      const int limit = maximum + MaxDegree + 1;
      while (p.size() > 1 && remaining_) {
        bool found = false;
        for (int a = 1; a <= int(MaxDegree + 1) && !found; ++a)
          for (int b = -limit; b <= limit; ++b) {
            if (std::gcd(a, std::abs(b)) != 1)
              continue;
            if (auto q = divideLinear(p, a, b)) {
              roots.emplace_back(a, b);
              p = std::move(*q);
              found = true;
              break;
            }
          }
        if (!found)
          break;
      }
      llvm::Value *residual = nullptr;
      for (auto it = p.rbegin(); it != p.rend(); ++it) {
        if (residual)
          residual = builder.CreateMul(residual, linear(1, 0, workType),
                                       "small.select.horner");
        auto *c = llvm::ConstantInt::get(workType, it->sextOrTrunc(workWidth));
        residual =
                residual ? builder.CreateAdd(residual, c, "small.select.horner")
                         : c;
      }
      Monomial product;
      auto coefficient = content.sextOrTrunc(width_);
      if (denominator != 1) {
        auto *numerator = builder.CreateMul(
                residual,
                llvm::ConstantInt::get(workType,
                                       content.sextOrTrunc(workWidth)),
                "small.select.numerator");
        for (auto [a, b]: roots) {
          auto *constant = llvm::dyn_cast<llvm::ConstantInt>(numerator);
          numerator =
                  constant && constant->isOne()
                          ? linear(a, b, workType)
                          : builder.CreateMul(numerator, linear(a, b, workType),
                                              "small.select.numerator");
        }
        auto *divisor = llvm::ConstantInt::get(workType, denominator);
        auto *quotient = nonnegative
                                 ? builder.CreateUDiv(numerator, divisor,
                                                      "small.select.quotient")
                                 : builder.CreateSDiv(numerator, divisor,
                                                      "small.select.quotient");
        product.push_back(intern(builder.CreateZExtOrTrunc(
                quotient, type, "small.select.coefficient")));
        coefficient = llvm::APInt(width_, 1);
      } else {
        if (auto *constant = llvm::dyn_cast<llvm::ConstantInt>(residual))
          coefficient *= constant->getValue();
        else
          product.push_back(intern(residual));
        for (auto [a, b]: roots)
          product.push_back(intern(linear(a, b, type)));
      }
      for (auto id: monomial) {
        auto [it, inserted] = frozenAtoms.try_emplace(id);
        if (inserted)
          it->second =
                  intern(builder.CreateFreeze(atoms_[id], "small.select.atom"));
        product.push_back(it->second);
      }
      std::sort(product.begin(), product.end());
      addTerm(terms, std::move(product), std::move(coefficient));
    }
    return factorSum(terms, builder, type, factors);
  }

  void reset() {
    // Delete no module instructions until all raw Value* identities are gone.
    memo_.clear();
    expanded_.clear();
    atomIDs_.clear();
    atoms_.clear();
  }

  public:
  bool runSelects() {
    llvm::SmallVector<llvm::WeakTrackingVH, 16> roots;
    for (auto &block: function_)
      for (auto &instruction: block)
        if (llvm::isa<llvm::SelectInst>(instruction) &&
            instruction.getType()->isIntegerTy())
          roots.emplace_back(&instruction);
    bool changed = false;
    for (auto cursor = roots.rbegin(); cursor != roots.rend() && remaining_;
         ++cursor) {
      auto *root = llvm::dyn_cast_or_null<llvm::SelectInst>(
              static_cast<llvm::Value *>(*cursor));
      if (!root || root->getType()->getIntegerBitWidth() > 256)
        continue;
      reset();
      const auto test = selectorCase(root);
      if (!test)
        continue;
      width_ = root->getType()->getIntegerBitWidth();
      llvm::SmallPtrSet<llvm::Value *, 16> seen;
      if (!gather(root, test->selector, seen))
        continue;
      const auto domain = selectDomain(root, test->selector, seen);
      if (!domain)
        continue;
      const unsigned count = domain->count();
      std::vector<Polynomial> rows;
      bool valid = true;
      for (unsigned value = 0; value < count; ++value) {
        auto polynomial = parse(leaf(root, domain->first + value));
        if (!polynomial) {
          valid = false;
          break;
        }
        rows.push_back(std::move(*polynomial));
      }
      if (!valid)
        continue;
      auto table = differences(rows);
      if (!table)
        continue;
      const auto oldCost = deadCost(root);
      // Speculative instructions live only in a detached block. A failed cost
      // check destroys it without changing any original instruction or use.
      std::unique_ptr<llvm::BasicBlock> scratch;
      llvm::Value *replacement = nullptr;
      unsigned bestCost = oldCost;
      for (bool factored: {true, false}) {
        std::unique_ptr<llvm::BasicBlock> candidate(
                llvm::BasicBlock::Create(function_.getContext()));
        llvm::IRBuilder<> builder(candidate.get());
        auto *selector =
                builder.CreateFreeze(test->selector, "small.select.selector");
        if (domain->clampLow)
          selector = builder.CreateSelect(
                  builder.CreateICmpSLT(
                          selector, llvm::ConstantInt::get(selector->getType(),
                                                           domain->first)),
                  llvm::ConstantInt::get(selector->getType(), domain->first),
                  selector, "small.select.clamp.low");
        if (domain->clampHigh)
          selector = builder.CreateSelect(
                  builder.CreateICmpSGT(
                          selector, llvm::ConstantInt::get(selector->getType(),
                                                           domain->last)),
                  llvm::ConstantInt::get(selector->getType(), domain->last),
                  selector, "small.select.clamp.high");
        if (!domain->first.isZero())
          selector = builder.CreateSub(
                  selector,
                  llvm::ConstantInt::get(selector->getType(), domain->first),
                  "small.select.offset");
        auto *type = llvm::cast<llvm::IntegerType>(root->getType());
        auto *value = factored ? buildFactoredSelect(*table, selector, type,
                                                     candidate.get(), count - 1)
                               : buildSelect(*table, selector, type,
                                             candidate.get(), count - 1);
        if (candidate->size() < bestCost) {
          if (scratch)
            scratch->dropAllReferences();
          bestCost = candidate->size();
          scratch = std::move(candidate);
          replacement = value;
        } else
          candidate->dropAllReferences();
      }
      if (!scratch)
        continue;
      root->getParent()->splice(root->getIterator(), scratch.get());
      root->replaceAllUsesWith(replacement);
      reset();
      llvm::RecursivelyDeleteTriviallyDeadInstructions(root);
      changed = true;
    }
    reset();
    return changed;
  }

  explicit ModularPolynomial(llvm::Function &function) :
      function_(function), dominators_(function) {}

  bool run() {
    // Visit consumers before producers, so a closed multi-instruction sum is
    // considered before its individual (already cheap) arithmetic terms.
    llvm::SmallVector<llvm::WeakTrackingVH, 32> roots;
    for (auto &block: function_)
      for (auto &instruction: block)
        if (llvm::isa<llvm::BinaryOperator>(instruction) &&
            instruction.getType()->isIntegerTy())
          roots.emplace_back(&instruction);
    bool changed = false;
    for (auto cursor = roots.rbegin(); cursor != roots.rend() && remaining_;
         ++cursor) {
      if (!*cursor)
        continue;
      auto *root = llvm::cast<llvm::Instruction>(*cursor);
      width_ = root->getType()->getIntegerBitWidth();
      memo_.clear();
      expanded_.clear();
      auto polynomial = parse(root);
      if (!polynomial || !expanded_.contains(root))
        continue;
      // Measure the actual factored DAG, not the expanded monomial count:
      // a shared atom can make Horner form cheaper than that estimate.
      const auto oldCost = deadCost(root);
      std::unique_ptr<llvm::BasicBlock> scratch(
              llvm::BasicBlock::Create(function_.getContext()));
      llvm::IRBuilder<> builder(scratch.get());
      std::vector<llvm::Value *> factors(atoms_.begin(), atoms_.end());
      auto *replacement = factorSum(
              *polynomial, builder,
              llvm::cast<llvm::IntegerType>(root->getType()), factors);
      if (scratch->size() >= oldCost) {
        scratch->dropAllReferences();
        continue;
      }
      root->getParent()->splice(root->getIterator(), scratch.get());
      root->replaceAllUsesWith(replacement);
      // Old atoms can be deleted with the cone. Never keep their raw pointer
      // identities across a rewrite: LLVM may reuse a freed Value's address.
      memo_.clear();
      expanded_.clear();
      atomIDs_.clear();
      atoms_.clear();
      llvm::RecursivelyDeleteTriviallyDeadInstructions(root);
      changed = true;
    }
    return changed;
  }
};

class ModularPolynomialPass
    : public llvm::PassInfoMixin<ModularPolynomialPass> {
  public:
  llvm::PreservedAnalyses run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &) {
    return ModularPolynomial(function).run() ? llvm::PreservedAnalyses::none()
                                             : llvm::PreservedAnalyses::all();
  }
};
class SmallSelectPolynomialPass
    : public llvm::PassInfoMixin<SmallSelectPolynomialPass> {
  public:
  llvm::PreservedAnalyses run(llvm::Function &function,
                              llvm::FunctionAnalysisManager &) {
    return ModularPolynomial(function).runSelects()
                   ? llvm::PreservedAnalyses::none()
                   : llvm::PreservedAnalyses::all();
  }
};
} // namespace

void dragon::llvmlifter::registerModularPolynomialPass(
        llvm::PassBuilder &builder) {
  builder.registerPipelineParsingCallback(
          [](llvm::StringRef name, llvm::FunctionPassManager &passes,
             llvm::ArrayRef<llvm::PassBuilder::PipelineElement> inner) {
            if (!inner.empty())
              return false;
            if (name == "dragon-normalize-modular-polynomials")
              passes.addPass(ModularPolynomialPass());
            else if (name == "dragon-fold-small-selects")
              passes.addPass(SmallSelectPolynomialPass());
            else
              return false;
            return true;
          });
}
