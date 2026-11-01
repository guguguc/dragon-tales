#include "Passes.hpp"

#include <llvm/ADT/APInt.h>
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassBuilder.h>

#include <array>
#include <optional>

namespace {
// This pass ADDS hypotheses, never replaces the original function. A consumer
// must independently prove entry, batch steps and real exits before selecting
// a candidate. Polynomial inversion alone says nothing about the tail or bound.
constexpr unsigned Degree = 3, Bits = 256;
using Poly = std::array<llvm::APInt, Degree + 1>;
Poly zero() {
  return {llvm::APInt(Bits, 0), llvm::APInt(Bits, 0), llvm::APInt(Bits, 0),
          llvm::APInt(Bits, 0)};
}
bool bounded(const Poly &p) {
  return llvm::all_of(p, [](const auto &c) { return c.isSignedIntN(120); });
}
std::optional<Poly> combine(Poly a, const Poly &b, bool subtract = false) {
  for (unsigned i = 0; i <= Degree; ++i)
    a[i] += subtract ? -b[i] : b[i];
  return bounded(a) ? std::optional(a) : std::nullopt;
}
std::optional<Poly> product(const Poly &a, const Poly &b) {
  auto p = zero();
  for (unsigned i = 0; i <= Degree; ++i)
    for (unsigned j = 0; j <= Degree; ++j) {
      if (a[i].isZero() || b[j].isZero())
        continue;
      if (i + j > Degree)
        return std::nullopt;
      p[i + j] += a[i] * b[j];
    }
  return bounded(p) ? std::optional(p) : std::nullopt;
}
class Reader {
  llvm::Value *iv_, *acc_;
  unsigned budget_ = 256;

  public:
  Reader(llvm::Value *iv, llvm::Value *acc) : iv_(iv), acc_(acc) {}
  std::optional<Poly> read(llvm::Value *value, unsigned depth = 0) {
    if (!budget_ || depth > 32)
      return std::nullopt;
    --budget_;
    auto p = zero();
    if (value == iv_) {
      p[1] = 1;
      return p;
    }
    if (auto *c = llvm::dyn_cast<llvm::ConstantInt>(value)) {
      p[0] = c->getValue().sextOrTrunc(Bits);
      return p;
    }
    auto *op = llvm::dyn_cast<llvm::BinaryOperator>(value);
    if (!op || op->hasNoSignedWrap() || op->hasNoUnsignedWrap())
      return std::nullopt;
    auto left = read(op->getOperand(0), depth + 1);
    if (!left)
      return std::nullopt;
    if (op->getOpcode() == llvm::Instruction::Shl) {
      auto *c = llvm::dyn_cast<llvm::ConstantInt>(op->getOperand(1));
      if (!c || c->getValue().uge(value->getType()->getIntegerBitWidth()))
        return std::nullopt;
      auto scale = zero();
      scale[0] = llvm::APInt::getOneBitSet(Bits, c->getZExtValue());
      return product(*left, scale);
    }
    auto right = read(op->getOperand(1), depth + 1);
    if (!right)
      return std::nullopt;
    switch (op->getOpcode()) {
      case llvm::Instruction::Add:
        return combine(*left, *right);
      case llvm::Instruction::Sub:
        return combine(*left, *right, true);
      case llvm::Instruction::Mul:
        return product(*left, *right);
      default:
        return std::nullopt;
    }
  }
  std::optional<Poly> delta(llvm::Value *value, unsigned depth = 0) {
    if (value == acc_)
      return zero();
    if (!budget_ || depth > 32)
      return std::nullopt;
    --budget_;
    auto *op = llvm::dyn_cast<llvm::BinaryOperator>(value);
    if (!op || op->hasNoSignedWrap() || op->hasNoUnsignedWrap())
      return std::nullopt;
    if (op->getOpcode() != llvm::Instruction::Add &&
        op->getOpcode() != llvm::Instruction::Sub)
      return std::nullopt;
    if (auto a = delta(op->getOperand(0), depth + 1))
      if (auto b = read(op->getOperand(1), depth + 1))
        return combine(*a, *b, op->getOpcode() == llvm::Instruction::Sub);
    if (op->getOpcode() == llvm::Instruction::Add)
      if (auto a = read(op->getOperand(0), depth + 1))
        if (auto b = delta(op->getOperand(1), depth + 1))
          return combine(*a, *b);
    return std::nullopt;
  }
};
unsigned choose(unsigned n, unsigned k) {
  unsigned result = 1;
  for (unsigned j = 1; j <= k; ++j)
    result = result * (n - j + 1) / j;
  return result;
}
unsigned power(unsigned x, unsigned n) {
  unsigned result = 1;
  while (n--)
    result *= x;
  return result;
}
std::optional<Poly> unbatch(Poly residual, unsigned stride) {
  auto q = zero();
  const llvm::APInt divisor(Bits, stride);
  for (int d = Degree; d >= 0; --d) {
    if (!residual[d].srem(divisor).isZero())
      return std::nullopt;
    q[d] = residual[d].sdiv(divisor);
    for (unsigned i = 0; i <= unsigned(d); ++i) {
      unsigned coefficient = 0;
      for (unsigned j = 0; j < stride; ++j)
        coefficient += choose(d, i) * power(j, d - i);
      residual[i] -= q[d] * coefficient;
    }
    if (!bounded(residual))
      return std::nullopt;
  }
  return q;
}
llvm::Value *emit(const Poly &p, llvm::Value *iv, llvm::IRBuilder<> &b) {
  auto *type = llvm::cast<llvm::IntegerType>(iv->getType());
  llvm::Value *result = nullptr;
  for (int i = Degree; i >= 0; --i) {
    if (result)
      result = b.CreateMul(result, iv);
    if (!p[i].isZero()) {
      auto *c = llvm::ConstantInt::get(type,
                                       p[i].sextOrTrunc(type->getBitWidth()));
      result = result ? b.CreateAdd(result, c) : c;
    }
  }
  return result ? result : llvm::ConstantInt::get(type, 0);
}
struct Model {
  llvm::PHINode *iv, *acc;
  llvm::ConstantInt *seed, *initial;
  unsigned stride;
  Poly delta;
};
std::optional<Model> model(llvm::Loop &loop) {
  auto *pre = loop.getLoopPreheader(), *latch = loop.getLoopLatch();
  if (!pre || !latch || loop.getNumBlocks() != 2 || !loop.getSubLoops().empty())
    return std::nullopt;
  llvm::SmallVector<llvm::PHINode *, 2> phis;
  for (auto &p: loop.getHeader()->phis())
    phis.push_back(&p);
  if (phis.size() != 2)
    return std::nullopt;
  for (unsigned index = 0; index < 2; ++index) {
    auto *iv = phis[index], *acc = phis[1 - index];
    if (iv->getType() != acc->getType() || !iv->getType()->isIntegerTy())
      continue;
    unsigned width = iv->getType()->getIntegerBitWidth();
    if (width < 8 || width > 64)
      continue;
    auto *seed = llvm::dyn_cast<llvm::ConstantInt>(
            iv->getIncomingValueForBlock(pre));
    auto *initial = llvm::dyn_cast<llvm::ConstantInt>(
            acc->getIncomingValueForBlock(pre));
    auto *next = llvm::dyn_cast<llvm::BinaryOperator>(
            iv->getIncomingValueForBlock(latch));
    if (!seed || !initial || seed->isNegative() || !next ||
        next->getOpcode() != llvm::Instruction::Add ||
        next->hasNoSignedWrap() || next->hasNoUnsignedWrap())
      continue;
    auto *step = llvm::dyn_cast<llvm::ConstantInt>(next->getOperand(1));
    if (next->getOperand(0) != iv || !step || step->getValue().ult(2) ||
        step->getValue().ugt(16))
      continue;
    auto batch = Reader(iv, acc).delta(acc->getIncomingValueForBlock(latch));
    if (!batch)
      continue;
    unsigned stride = step->getZExtValue();
    auto scalar = unbatch(*batch, stride);
    if (scalar)
      return Model{iv, acc, seed, initial, stride, *scalar};
  }
  return std::nullopt;
}
void propose(llvm::Function &source, const Model &m, llvm::Value *bound,
             unsigned index) {
  auto *module = source.getParent();
  auto name = source.getName() + ".dragon.scalar." + llvm::Twine(index);
  if (module->getFunction(name.str()))
    return;
  auto *f = llvm::Function::Create(source.getFunctionType(),
                                   llvm::GlobalValue::ExternalLinkage, name,
                                   module);
  auto *entry = llvm::BasicBlock::Create(source.getContext(), "entry", f);
  auto *loop = llvm::BasicBlock::Create(source.getContext(), "loop", f);
  auto *exit = llvm::BasicBlock::Create(source.getContext(), "exit", f);
  for (unsigned i = 0; i < f->arg_size(); ++i) {
    f->getArg(i)->setName(source.getArg(i)->getName());
    if (source.getArg(i)->hasAttribute(llvm::Attribute::NoUndef))
      f->getArg(i)->addAttr(llvm::Attribute::NoUndef);
  }
  llvm::IRBuilder<> b(entry);
  llvm::Value *limit;
  if (auto *a = llvm::dyn_cast<llvm::Argument>(bound))
    limit = f->getArg(a->getArgNo());
  else {
    auto *trunc = llvm::cast<llvm::TruncInst>(bound);
    auto *input = llvm::cast<llvm::Argument>(trunc->getOperand(0));
    limit = b.CreateTrunc(f->getArg(input->getArgNo()), m.iv->getType());
  }
  b.CreateCondBr(b.CreateICmpSGE(limit, m.seed), loop, exit);
  b.SetInsertPoint(loop);
  auto *iv = b.CreatePHI(m.iv->getType(), 2, "iv");
  auto *acc = b.CreatePHI(m.acc->getType(), 2, "acc");
  auto *value = b.CreateAdd(acc, emit(m.delta, iv, b));
  auto *next = b.CreateAdd(iv, llvm::ConstantInt::get(iv->getType(), 1));
  b.CreateCondBr(b.CreateICmpEQ(iv, limit), exit, loop);
  iv->addIncoming(m.seed, entry);
  iv->addIncoming(next, loop);
  acc->addIncoming(m.initial, entry);
  acc->addIncoming(value, loop);
  b.SetInsertPoint(exit);
  auto *result = b.CreatePHI(acc->getType(), 2, "result");
  result->addIncoming(m.initial, entry);
  result->addIncoming(value, loop);
  b.CreateRet(b.CreateZExtOrTrunc(result, source.getReturnType()));
}
class ScalarLoopProposalPass
    : public llvm::PassInfoMixin<ScalarLoopProposalPass> {
  public:
  llvm::PreservedAnalyses run(llvm::Module &module,
                              llvm::ModuleAnalysisManager &manager) {
    auto &functions =
            manager.getResult<llvm::FunctionAnalysisManagerModuleProxy>(module)
                    .getManager();
    llvm::SmallVector<llvm::Function *, 4> originals;
    for (auto &f: module)
      if (!f.isDeclaration() && !f.getName().contains(".dragon.scalar."))
        originals.push_back(&f);
    bool changed = false;
    for (auto *f: originals) {
      if (!f->getReturnType()->isIntegerTy())
        continue;
      auto &loops = functions.getResult<llvm::LoopAnalysis>(*f);
      if (std::distance(loops.begin(), loops.end()) != 1)
        continue;
      auto m = model(**loops.begin());
      if (!m || f->getReturnType()->getIntegerBitWidth() <
                        m->iv->getType()->getIntegerBitWidth())
        continue;
      llvm::SmallVector<llvm::Value *, 4> bounds;
      for (auto &arg: f->args())
        if (arg.getType() == m->iv->getType())
          bounds.push_back(&arg);
      for (auto &block: *f)
        for (auto &i: block)
          if (auto *trunc = llvm::dyn_cast<llvm::TruncInst>(&i))
            if (trunc->getType() == m->iv->getType() &&
                llvm::isa<llvm::Argument>(trunc->getOperand(0)))
              bounds.push_back(trunc);
      for (unsigned i = 0; i < std::min<unsigned>(4, bounds.size()); ++i) {
        propose(*f, *m, bounds[i], i);
        changed = true;
      }
    }
    return changed ? llvm::PreservedAnalyses::none()
                   : llvm::PreservedAnalyses::all();
  }
};
} // namespace
void dragon::llvmlifter::registerScalarLoopProposalPass(
        llvm::PassBuilder &builder) {
  builder.registerPipelineParsingCallback(
          [](llvm::StringRef name, llvm::ModulePassManager &passes,
             llvm::ArrayRef<llvm::PassBuilder::PipelineElement> inner) {
            if (name != "dragon-propose-scalar-loops" || !inner.empty())
              return false;
            passes.addPass(ScalarLoopProposalPass());
            return true;
          });
}
