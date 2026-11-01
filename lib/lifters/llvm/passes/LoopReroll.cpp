#include <dragon/lifters/llvm/LLVMLifter.hpp>

#include <llvm/ADT/DenseMap.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/AsmParser/Parser.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/SourceMgr.h>

#include <optional>

namespace {
// Fixed-trip rerolling of closed, scalar integer recurrences. This is not
// symbolic loop discovery: trip count comes from the actual repeated chain.
// No samples, source formulas, VM roles or concrete machine addresses are used.
struct Round {
  llvm::Value *seed;
  llvm::Instruction *out;
  llvm::SmallVector<llvm::Instruction *, 8> body;
};
struct Chain {
  llvm::SmallVector<Round, 8> rounds;
};

bool eligible(const llvm::Instruction &i) {
  if (!i.getType()->isIntegerTy() || i.hasMetadataOtherThanDebugLoc())
    return false;
  switch (i.getOpcode()) {
    case llvm::Instruction::Add:
    case llvm::Instruction::Sub:
    case llvm::Instruction::Mul:
    case llvm::Instruction::And:
    case llvm::Instruction::Or:
    case llvm::Instruction::Xor:
    case llvm::Instruction::Shl:
    case llvm::Instruction::LShr:
    case llvm::Instruction::AShr:
    case llvm::Instruction::Trunc:
    case llvm::Instruction::ZExt:
    case llvm::Instruction::SExt:
    case llvm::Instruction::ICmp:
    case llvm::Instruction::Select:
      return true;
    default:
      // In particular: no memory, calls, freeze, division, FP or vectors.
      return false;
  }
}

// Exact ordered graph isomorphism, including semantic flags and full-width
// constants. No hash is ever accepted as evidence that two rounds are equal.
bool identical(const Round &a, const Round &b) {
  if (a.body.size() != b.body.size() || a.seed->getType() != b.seed->getType())
    return false;
  llvm::DenseMap<const llvm::Value *, const llvm::Value *> map;
  map[a.seed] = b.seed;
  for (unsigned n = 0; n < a.body.size(); ++n) {
    const auto *x = a.body[n], *y = b.body[n];
    if (!x->isSameOperationAs(y) || !x->hasSameSubclassOptionalData(y))
      return false;
    for (unsigned j = 0; j < x->getNumOperands(); ++j) {
      const auto *p = x->getOperand(j), *q = y->getOperand(j);
      if (llvm::isa<llvm::ConstantInt>(p)) {
        if (p != q)
          return false;
      } else if (map.lookup(p) != q)
        return false;
    }
    map[x] = y;
  }
  return map.lookup(a.out) == b.out;
}

bool closed(const Chain &chain) {
  llvm::SmallPtrSet<llvm::Instruction *, 32> all;
  for (const auto &round: chain.rounds)
    for (auto *i: round.body)
      if (!all.insert(i).second)
        return false;
  for (auto *i: all) {
    if (i == chain.rounds.back().out)
      continue;
    for (auto *user: i->users()) {
      const auto *instruction = llvm::dyn_cast<llvm::Instruction>(user);
      if (!instruction || !all.contains(instruction))
        return false;
    }
  }
  return true;
}

class Matcher {
  // Whole invocation budgets bound optimization cost, not program semantics.
  unsigned budget_ = 500000;
  static constexpr unsigned MaxBody = 64, MaxScan = 4096;

  std::optional<Round> slice(llvm::Instruction *out, llvm::Value *seed) {
    llvm::SmallPtrSet<llvm::Instruction *, 32> need;
    llvm::SmallVector<llvm::Value *, 16> pending{out};
    bool reachesSeed = false;
    while (!pending.empty()) {
      if (!budget_)
        return std::nullopt;
      --budget_;
      auto *v = pending.pop_back_val();
      if (v == seed) {
        reachesSeed = true;
        continue;
      }
      if (llvm::isa<llvm::ConstantInt>(v))
        continue;
      auto *i = llvm::dyn_cast<llvm::Instruction>(v);
      if (!i || i->getParent() != out->getParent() || !eligible(*i))
        return std::nullopt;
      if (!need.insert(i).second)
        continue;
      if (need.size() > MaxBody)
        return std::nullopt;
      for (auto &operand: i->operands())
        pending.push_back(operand.get());
    }
    if (!reachesSeed)
      return std::nullopt;
    Round result{seed, out, {}};
    // Same-block SSA order is topological and deterministic, unlike pointer
    // set iteration. No recursive stack growth on large expression chains.
    for (auto &i: *out->getParent()) {
      if (need.contains(&i))
        result.body.push_back(&i);
      if (&i == out)
        break;
    }
    if (result.body.size() != need.size())
      return std::nullopt;
    return result;
  }

  llvm::SmallVector<Round, 8> candidates(llvm::Value *seed,
                                         llvm::BasicBlock &block) {
    llvm::SmallVector<Round, 8> result;
    llvm::SmallPtrSet<llvm::Value *, 32> available;
    available.insert(seed);
    auto *instruction = llvm::dyn_cast<llvm::Instruction>(seed);
    auto *start = instruction ? instruction->getNextNode() : &block.front();
    unsigned scanned = 0;
    for (auto *i = start; i && budget_ && scanned < MaxScan;
         i = i->getNextNode(), ++scanned) {
      --budget_;
      if (!eligible(*i))
        continue;
      bool ready = true;
      for (auto &operand: i->operands())
        if (!llvm::isa<llvm::ConstantInt>(operand.get()) &&
            !available.contains(operand.get())) {
          ready = false;
          break;
        }
      if (!ready)
        continue;
      available.insert(i);
      if (i->getType() == seed->getType())
        if (auto round = slice(i, seed))
          result.push_back(std::move(*round));
    }
    return result;
  }

  public:
  std::optional<Chain> find(llvm::Function &function) {
    std::optional<Chain> best;
    std::size_t bestSaving = 0;
    auto consider = [&](llvm::Value *seed, llvm::BasicBlock &block) {
      if (!seed->getType()->isIntegerTy() || !budget_)
        return;
      for (auto &first: candidates(seed, block)) {
        Chain chain;
        chain.rounds.push_back(first);
        while (budget_ && chain.rounds.size() < MaxScan) {
          std::optional<Round> next;
          for (auto &candidate: candidates(chain.rounds.back().out, block))
            if (identical(first, candidate)) {
              next = std::move(candidate);
              break;
            }
          if (!next)
            break;
          chain.rounds.push_back(std::move(*next));
        }
        auto saving = (chain.rounds.size() - 1) * first.body.size();
        // Two PHIs, induction increment, comparison and extra branches have a
        // cost. Avoid making short, already compact regions larger.
        if (chain.rounds.size() >= 2 && saving > 6 && saving > bestSaving &&
            closed(chain)) {
          bestSaving = saving;
          best = std::move(chain);
        }
      }
    };
    for (auto &block: function) {
      // Existing loop headers are not reinterpreted as straight-line chains.
      if (!block.phis().empty())
        continue;
      for (auto &arg: function.args())
        consider(&arg, block);
      for (auto &i: block)
        consider(&i, block);
    }
    return best;
  }
};

void rewrite(Chain &chain) {
  auto &first = chain.rounds.front();
  auto &last = chain.rounds.back();
  auto *entry = first.out->getParent();
  auto *function = entry->getParent();
  auto &ctx = entry->getContext();
  auto *exit = entry->splitBasicBlock(first.body.front(), "reroll.exit");
  auto *header = llvm::BasicBlock::Create(ctx, "reroll.header", function, exit);
  llvm::cast<llvm::BranchInst>(entry->getTerminator())->setSuccessor(0, header);
  llvm::IRBuilder<> b(header);
  auto *counter = b.CreatePHI(b.getInt32Ty(), 2, "reroll.iv");
  auto *accumulator = b.CreatePHI(first.seed->getType(), 2, "reroll.acc");
  counter->addIncoming(b.getInt32(0), entry);
  accumulator->addIncoming(first.seed, entry);
  llvm::DenseMap<llvm::Value *, llvm::Value *> map;
  map[first.seed] = accumulator;
  for (auto *original: first.body) {
    auto *cloned = original->clone();
    for (unsigned i = 0; i < cloned->getNumOperands(); ++i)
      if (auto it = map.find(cloned->getOperand(i)); it != map.end())
        cloned->setOperand(i, it->second);
    b.Insert(cloned);
    map[original] = cloned;
  }
  auto *result = map.lookup(first.out);
  auto *next = b.CreateAdd(counter, b.getInt32(1), "reroll.iv.next");
  counter->addIncoming(next, header);
  accumulator->addIncoming(result, header);
  auto *again =
          b.CreateICmpULT(next, b.getInt32(chain.rounds.size()), "reroll.more");
  b.CreateCondBr(again, header, exit);
  last.out->replaceAllUsesWith(result);
  // Every non-final use was checked before mutation. Delete in reverse
  // dependency order, with no poison replacement to conceal remaining uses.
  for (auto r = chain.rounds.rbegin(); r != chain.rounds.rend(); ++r)
    for (auto i = r->body.rbegin(); i != r->body.rend(); ++i)
      (*i)->eraseFromParent();
}
} // namespace

bool dragon::llvmlifter::LLVMLifter::loadIR(std::string_view text) {
  llvm::SMDiagnostic diagnostic;
  auto parsed = llvm::parseAssemblyString(
          llvm::StringRef(text.data(), text.size()), diagnostic, *ctx_);
  if (!parsed || llvm::verifyModule(*parsed))
    return false;
  module_ = std::move(parsed);
  return true;
}

std::size_t dragon::llvmlifter::LLVMLifter::runLoopReroll() {
  std::size_t count = 0;
  Matcher matcher;
  for (auto &function: *module_) {
    if (function.isDeclaration())
      continue;
    while (auto chain = matcher.find(function)) {
      rewrite(*chain);
      ++count;
    }
  }
  return count;
}
