#include <dragon/lifters/ignil/MemoryEffects.hpp>
#include <dragon/lifters/llvm/LLVMLifter.hpp>
#include <llvm/IR/Verifier.h>
#include <z3++.h>

#include <unordered_map>
#include <unordered_set>

namespace {
unsigned width(const z3::expr &e) {
  return e.is_bool() ? 1 : e.is_bv() ? e.get_sort().bv_size() : 0;
}

bool supported(const z3::expr &e) {
  const auto n = e.num_args();
  switch (e.decl().decl_kind()) {
    case Z3_OP_TRUE:
    case Z3_OP_FALSE:
    case Z3_OP_BNUM:
      return n == 0;
    case Z3_OP_NOT:
    case Z3_OP_BNOT:
    case Z3_OP_BNEG:
    case Z3_OP_EXTRACT:
    case Z3_OP_ZERO_EXT:
    case Z3_OP_SIGN_EXT:
      return n == 1;
    case Z3_OP_BADD:
    case Z3_OP_BSUB:
    case Z3_OP_BMUL:
    case Z3_OP_BAND:
    case Z3_OP_BOR:
    case Z3_OP_BXOR:
    case Z3_OP_AND:
    case Z3_OP_OR:
    case Z3_OP_XOR:
    case Z3_OP_CONCAT:
      return n >= 2;
    case Z3_OP_BUDIV:
    case Z3_OP_BUREM:
    case Z3_OP_BSDIV:
    case Z3_OP_BSREM:
    case Z3_OP_BSMOD:
    case Z3_OP_BUDIV_I:
    case Z3_OP_BUREM_I:
    case Z3_OP_BSDIV_I:
    case Z3_OP_BSREM_I:
    case Z3_OP_BSMOD_I:
    case Z3_OP_BSHL:
    case Z3_OP_BLSHR:
    case Z3_OP_BASHR:
    case Z3_OP_EQ:
    case Z3_OP_DISTINCT:
    case Z3_OP_IMPLIES:
    case Z3_OP_ULT:
    case Z3_OP_ULEQ:
    case Z3_OP_UGT:
    case Z3_OP_UGEQ:
    case Z3_OP_SLT:
    case Z3_OP_SLEQ:
    case Z3_OP_SGT:
    case Z3_OP_SGEQ:
      return n == 2;
    case Z3_OP_ITE:
      return n == 3;
    default:
      return false;
  }
}
using Values = std::unordered_map<unsigned, llvm::Value *>;
llvm::Value *lowerDirect(llvm::LLVMContext &ctx, llvm::IRBuilder<> &b,
                         Values &values, const z3::expr &recovered) {
  std::unordered_set<unsigned> visited;
  // Validate the whole DAG before emitting instructions or changing values.
  // Keep the word-level structure recovered by construction-time folding.
  std::vector<std::pair<z3::expr, bool>> pending{{recovered, false}};
  std::vector<z3::expr> order;
  while (!pending.empty()) {
    auto [e, expanded] = pending.back();
    pending.pop_back();
    if (visited.contains(e.id()))
      continue;
    if (!width(e) || width(e) > 4096 || !e.is_app())
      return nullptr;
    if (!values.contains(e.id()) && !supported(e))
      return nullptr;
    if (!expanded && !values.contains(e.id()) && e.num_args()) {
      pending.emplace_back(e, true);
      for (unsigned i = e.num_args(); i > 0; --i)
        pending.emplace_back(e.arg(i - 1), false);
    } else {
      visited.insert(e.id());
      order.push_back(e);
    }
  }
  for (const auto &e: order) {
    if (values.contains(e.id()))
      continue;
    auto arg = [&](unsigned i) { return values.at(e.arg(i).id()); };
    auto *ty = llvm::IntegerType::get(ctx, width(e));
    llvm::Value *v = nullptr;
    switch (e.decl().decl_kind()) {
      case Z3_OP_TRUE:
        v = b.getTrue();
        break;
      case Z3_OP_FALSE:
        v = b.getFalse();
        break;
      case Z3_OP_BNUM:
        v = llvm::ConstantInt::get(
                ctx,
                llvm::APInt(width(e), Z3_get_numeral_string(e.ctx(), e), 10));
        break;
      case Z3_OP_BNOT:
      case Z3_OP_NOT:
        v = b.CreateNot(arg(0));
        break;
      case Z3_OP_BNEG:
        v = b.CreateNeg(arg(0));
        break;
      case Z3_OP_ZERO_EXT:
        v = b.CreateZExtOrTrunc(arg(0), ty);
        break;
      case Z3_OP_SIGN_EXT:
        v = b.CreateSExtOrTrunc(arg(0), ty);
        break;
      case Z3_OP_EXTRACT:
        v = arg(0);
        if (e.lo())
          v = b.CreateLShr(v, llvm::ConstantInt::get(v->getType(), e.lo()));
        v = b.CreateZExtOrTrunc(v, ty);
        break;
      case Z3_OP_CONCAT:
        v = arg(0);
        for (unsigned i = 1; i < e.num_args(); ++i) {
          auto loWidth = width(e.arg(i));
          auto *wide = llvm::IntegerType::get(
                  ctx, v->getType()->getIntegerBitWidth() + loWidth);
          v = b.CreateOr(b.CreateShl(b.CreateZExt(v, wide),
                                     llvm::ConstantInt::get(wide, loWidth)),
                         b.CreateZExt(arg(i), wide));
        }
        break;
      case Z3_OP_BADD:
      case Z3_OP_BSUB:
      case Z3_OP_BMUL:
      case Z3_OP_BAND:
      case Z3_OP_BOR:
      case Z3_OP_BXOR:
      case Z3_OP_AND:
      case Z3_OP_OR:
      case Z3_OP_XOR:
        v = arg(0);
        for (unsigned i = 1; i < e.num_args(); ++i) {
          switch (e.decl().decl_kind()) {
            case Z3_OP_BADD:
              v = b.CreateAdd(v, arg(i));
              break;
            case Z3_OP_BSUB:
              v = b.CreateSub(v, arg(i));
              break;
            case Z3_OP_BMUL:
              v = b.CreateMul(v, arg(i));
              break;
            case Z3_OP_BAND:
            case Z3_OP_AND:
              v = b.CreateAnd(v, arg(i));
              break;
            case Z3_OP_BOR:
            case Z3_OP_OR:
              v = b.CreateOr(v, arg(i));
              break;
            default:
              v = b.CreateXor(v, arg(i));
              break;
          }
        }
        break;
      case Z3_OP_BUDIV:
      case Z3_OP_BUREM:
      case Z3_OP_BSDIV:
      case Z3_OP_BSREM:
      case Z3_OP_BSMOD:
      case Z3_OP_BUDIV_I:
      case Z3_OP_BUREM_I:
      case Z3_OP_BSDIV_I:
      case Z3_OP_BSREM_I:
      case Z3_OP_BSMOD_I: {
        const auto kind = e.decl().decl_kind();
        const bool unsignedDiv = kind == Z3_OP_BUDIV || kind == Z3_OP_BUDIV_I;
        const bool unsignedRem = kind == Z3_OP_BUREM || kind == Z3_OP_BUREM_I;
        const bool signedDiv = kind == Z3_OP_BSDIV || kind == Z3_OP_BSDIV_I;
        const bool signedMod = kind == Z3_OP_BSMOD || kind == Z3_OP_BSMOD_I;
        const bool isSigned = !unsignedDiv && !unsignedRem;
        // In i1, the literal 1 is also signed MIN/-1. No nonzero safe
        // divisor avoids overflow, so lower the total truth table directly.
        if (width(e) == 1) {
          auto *notDivisor = b.CreateNot(arg(1));
          v = (unsignedDiv || signedDiv) ? b.CreateOr(arg(0), notDivisor)
                                         : b.CreateAnd(arg(0), notDivisor);
          break;
        }
        auto *zero = llvm::ConstantInt::get(ty, 0);
        auto *one = llvm::ConstantInt::get(ty, 1);
        auto *minusOne = llvm::ConstantInt::getSigned(ty, -1);
        auto *byZero = b.CreateICmpEQ(arg(1), zero);
        llvm::Value *invalid = byZero;
        if (isSigned) {
          auto *minimum = llvm::ConstantInt::get(
                  ctx, llvm::APInt::getSignedMinValue(width(e)));
          invalid = b.CreateOr(byZero,
                               b.CreateAnd(b.CreateICmpEQ(arg(0), minimum),
                                           b.CreateICmpEQ(arg(1), minusOne)));
        }
        // SMT BV division/remainder are total. A select of a bad division's
        // RESULT would still execute LLVM UB, so guard the divisor itself.
        // MIN/-1 uses divisor 1: quotient MIN, remainder zero, exactly SMT.
        auto *divisor = b.CreateSelect(invalid, one, arg(1));
        llvm::Value *value;
        if (unsignedDiv)
          value = b.CreateUDiv(arg(0), divisor);
        else if (unsignedRem)
          value = b.CreateURem(arg(0), divisor);
        else if (signedDiv)
          value = b.CreateSDiv(arg(0), divisor);
        else {
          value = b.CreateSRem(arg(0), divisor);
          if (signedMod) {
            auto *differentSigns =
                    b.CreateICmpSLT(b.CreateXor(value, arg(1)), zero);
            auto *adjust =
                    b.CreateAnd(b.CreateICmpNE(value, zero), differentSigns);
            value = b.CreateSelect(adjust, b.CreateAdd(value, arg(1)), value);
          }
        }
        llvm::Value *fallback = arg(0); // rem/mod by zero returns the dividend.
        if (unsignedDiv)
          fallback = minusOne;
        else if (signedDiv)
          fallback =
                  b.CreateSelect(b.CreateICmpSLT(arg(0), zero), one, minusOne);
        v = b.CreateSelect(byZero, fallback, value);
        break;
      }
      case Z3_OP_BSHL:
      case Z3_OP_BLSHR:
      case Z3_OP_BASHR: {
        // SMT bit-vector shifts are total, whereas LLVM overshifts are poison.
        auto *inRange =
                b.CreateICmpULT(arg(1), llvm::ConstantInt::get(ty, width(e)));
        auto *amount =
                b.CreateSelect(inRange, arg(1), llvm::ConstantInt::get(ty, 0));
        llvm::Value *shifted, *fallback = llvm::ConstantInt::get(ty, 0);
        if (e.decl().decl_kind() == Z3_OP_BSHL)
          shifted = b.CreateShl(arg(0), amount);
        else if (e.decl().decl_kind() == Z3_OP_BLSHR)
          shifted = b.CreateLShr(arg(0), amount);
        else {
          shifted = b.CreateAShr(arg(0), amount);
          fallback = b.CreateAShr(arg(0),
                                  llvm::ConstantInt::get(ty, width(e) - 1));
        }
        v = b.CreateSelect(inRange, shifted, fallback);
        break;
      }
      case Z3_OP_ITE:
        v = b.CreateSelect(arg(0), arg(1), arg(2));
        break;
      case Z3_OP_IMPLIES:
        v = b.CreateOr(b.CreateNot(arg(0)), arg(1));
        break;
      case Z3_OP_EQ:
        v = b.CreateICmpEQ(arg(0), arg(1));
        break;
      case Z3_OP_DISTINCT:
        v = b.CreateICmpNE(arg(0), arg(1));
        break;
      case Z3_OP_ULT:
        v = b.CreateICmpULT(arg(0), arg(1));
        break;
      case Z3_OP_ULEQ:
        v = b.CreateICmpULE(arg(0), arg(1));
        break;
      case Z3_OP_UGT:
        v = b.CreateICmpUGT(arg(0), arg(1));
        break;
      case Z3_OP_UGEQ:
        v = b.CreateICmpUGE(arg(0), arg(1));
        break;
      case Z3_OP_SLT:
        v = b.CreateICmpSLT(arg(0), arg(1));
        break;
      case Z3_OP_SLEQ:
        v = b.CreateICmpSLE(arg(0), arg(1));
        break;
      case Z3_OP_SGT:
        v = b.CreateICmpSGT(arg(0), arg(1));
        break;
      case Z3_OP_SGEQ:
        v = b.CreateICmpSGE(arg(0), arg(1));
        break;
      default:
        break; // The prevalidation above makes this unreachable.
    }
    values.emplace(e.id(), v);
  }
  return values.at(recovered.id());
}

llvm::Value *lowerExpression(llvm::LLVMContext &ctx, llvm::IRBuilder<> &b,
                             Values &values, const z3::expr &expression) {
  if (auto *value = lowerDirect(ctx, b, values, expression))
    return value;
  // Exact fallback removes algebraically dead unsupported dependencies, e.g.
  // unknown high bits beneath a low-bit extract. A failed direct validation
  // leaves both the builder and previously lowered memory-event values intact.
  // Do not normalize successful DAGs: Z3 can expand shifts/XORs into bit
  // slices.
  const auto normalized = expression.simplify();
  return lowerDirect(ctx, b, values, normalized);
}

bool validArguments(z3::context &ctx, const std::vector<z3::expr> &arguments) {
  std::unordered_set<unsigned> ids;
  for (const auto &a: arguments)
    if (&a.ctx() != &ctx || !width(a) || width(a) > 4096 || !a.is_const() ||
        a.decl().decl_kind() != Z3_OP_UNINTERPRETED ||
        !ids.insert(a.id()).second)
      return false;
  return true;
}
} // namespace

bool dragon::llvmlifter::LLVMLifter::liftExpression(
        const z3::expr &expression, const std::vector<z3::expr> &arguments,
        std::string_view name) {
  return liftExpression(expression, arguments, name, {});
}

bool dragon::llvmlifter::LLVMLifter::liftExpression(
        const z3::expr &expression, const std::vector<z3::expr> &arguments,
        std::string_view name, const std::vector<ExpressionCall> &calls) {
  if (module_->getFunction(name.empty() ? "recovered" : std::string(name)))
    return false;
  if (!width(expression) || width(expression) > 4096 ||
      !validArguments(expression.ctx(), arguments))
    return false;
  std::vector<llvm::Type *> types;
  for (const auto &a: arguments)
    types.push_back(llvm::IntegerType::get(*ctx_, width(a)));
  auto *fn = llvm::Function::Create(
          llvm::FunctionType::get(
                  llvm::IntegerType::get(*ctx_, width(expression)), types,
                  false),
          llvm::GlobalValue::ExternalLinkage,
          name.empty() ? "recovered" : std::string(name), *module_);
  Values values;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    fn->getArg(i)->setName(arguments[i].decl().name().str());
    // A BV input denotes an arbitrary concrete word, never LLVM undef/poison.
    // State that existing interface contract explicitly so DivRemPairs need
    // not insert freeze instructions before sharing quotient/remainder work.
    fn->getArg(i)->addAttr(llvm::Attribute::NoUndef);
    values.emplace(arguments[i].id(), fn->getArg(i));
  }
  llvm::IRBuilder<> b(llvm::BasicBlock::Create(*ctx_, "entry", fn));
  std::vector<llvm::Function *> callees;
  for (const auto &call: calls) {
    auto *callee = module_->getFunction(call.function);
    if (!call.result || &call.result->ctx() != &expression.ctx() ||
        !validArguments(expression.ctx(), {*call.result}) ||
        values.contains(call.result->id()) || !callee || callee == fn ||
        callee->isDeclaration() || callee->isVarArg() ||
        callee->arg_size() != call.arguments.size() ||
        !callee->getReturnType()->isIntegerTy(width(*call.result))) {
      fn->eraseFromParent();
      return false;
    }
    std::vector<llvm::Value *> operands;
    for (std::size_t i = 0; i < call.arguments.size(); ++i) {
      const auto &argument = call.arguments[i];
      auto *value = &argument.ctx() == &expression.ctx()
                            ? lowerExpression(*ctx_, b, values, argument)
                            : nullptr;
      if (!value || value->getType() != callee->getArg(i)->getType()) {
        fn->eraseFromParent();
        return false;
      }
      operands.push_back(value);
    }
    auto *value = b.CreateCall(callee, operands, "call.result");
    values.emplace(call.result->id(), value);
    callees.push_back(callee);
  }
  auto *returned = lowerExpression(*ctx_, b, values, expression);
  if (!returned) {
    fn->eraseFromParent();
    return false;
  }
  b.CreateRet(returned);
  if (llvm::verifyFunction(*fn)) {
    fn->eraseFromParent();
    return false;
  }
  // Preserve recovered boundaries through the normal O2 pipeline. This is
  // independent of whether the original compiler used an inlining attribute.
  for (auto *callee: callees)
    callee->addFnAttr(llvm::Attribute::NoInline);
  return true;
}

bool dragon::llvmlifter::LLVMLifter::liftLoopRegion(
        const std::vector<z3::expr> &inputs,
        const std::vector<z3::expr> &carried, const std::vector<z3::expr> &next,
        const z3::expr &continuation, std::string_view name) {
  if (carried.empty() || carried.size() != next.size() ||
      width(continuation) != 1)
    return false;
  std::vector<z3::expr> arguments(inputs);
  arguments.insert(arguments.end(), carried.begin(), carried.end());
  if (!validArguments(continuation.ctx(), arguments))
    return false;
  for (std::size_t i = 0; i < carried.size(); ++i)
    if (&next[i].ctx() != &continuation.ctx() ||
        !z3::eq(next[i].get_sort(), carried[i].get_sort()))
      return false;
  std::vector<llvm::Type *> types, fields;
  for (const auto &arg: arguments)
    types.push_back(llvm::IntegerType::get(*ctx_, width(arg)));
  for (const auto &arg: carried)
    fields.push_back(llvm::IntegerType::get(*ctx_, width(arg)));
  auto *resultType = llvm::StructType::get(*ctx_, fields);
  auto *fn = llvm::Function::Create(
          llvm::FunctionType::get(resultType, types, false),
          llvm::GlobalValue::ExternalLinkage,
          name.empty() ? "loop_region" : std::string(name), *module_);
  auto fail = [&]() {
    fn->eraseFromParent();
    return false;
  };
  auto *entry = llvm::BasicBlock::Create(*ctx_, "entry", fn);
  auto *header = llvm::BasicBlock::Create(*ctx_, "loop.header", fn);
  auto *body = llvm::BasicBlock::Create(*ctx_, "loop.body", fn);
  auto *exit = llvm::BasicBlock::Create(*ctx_, "loop.exit", fn);
  llvm::IRBuilder<> b(entry);
  b.CreateBr(header);
  b.SetInsertPoint(header);
  Values values;
  for (std::size_t i = 0; i < inputs.size(); ++i) {
    fn->getArg(i)->setName(inputs[i].decl().name().str());
    values.emplace(inputs[i].id(), fn->getArg(i));
  }
  std::vector<llvm::PHINode *> phis;
  for (std::size_t i = 0; i < carried.size(); ++i) {
    auto *initial = fn->getArg(inputs.size() + i);
    initial->setName(carried[i].decl().name().str() + ".initial");
    auto *phi = b.CreatePHI(fields[i], 2, carried[i].decl().name().str());
    phi->addIncoming(initial, entry);
    phis.push_back(phi);
    values.emplace(carried[i].id(), phi);
  }
  auto *condition = lowerExpression(*ctx_, b, values, continuation);
  if (!condition)
    return fail();
  b.CreateCondBr(condition, body, exit);
  b.SetInsertPoint(body);
  std::vector<llvm::Value *> updates;
  for (const auto &expression: next) {
    auto *update = lowerExpression(*ctx_, b, values, expression);
    if (!update)
      return fail();
    updates.push_back(update);
  }
  // Parallel updates: every RHS was lowered using only the header PHIs.
  for (std::size_t i = 0; i < phis.size(); ++i)
    phis[i]->addIncoming(updates[i], body);
  b.CreateBr(header);
  b.SetInsertPoint(exit);
  llvm::Value *result = llvm::UndefValue::get(resultType);
  for (std::size_t i = 0; i < phis.size(); ++i)
    result = b.CreateInsertValue(result, phis[i], {static_cast<unsigned>(i)});
  b.CreateRet(result);
  if (llvm::verifyFunction(*fn))
    return fail();
  return true;
}

bool dragon::llvmlifter::LLVMLifter::liftLoopFunction(
        const std::vector<z3::expr> &inputs,
        const std::vector<z3::expr> &carried,
        const std::vector<z3::expr> &initial, const std::vector<z3::expr> &next,
        const z3::expr &continuation, const z3::expr &returned,
        std::string_view name, const z3::expr *entryGuard,
        const z3::expr *otherwise) {
  if (carried.size() != next.size() || carried.size() != initial.size() ||
      width(continuation) != 1 || !width(returned) || width(returned) > 4096 ||
      &returned.ctx() != &continuation.ctx() ||
      bool(entryGuard) != bool(otherwise))
    return false;
  if (entryGuard &&
      (&entryGuard->ctx() != &continuation.ctx() ||
       &otherwise->ctx() != &continuation.ctx() || width(*entryGuard) != 1 ||
       !z3::eq(otherwise->get_sort(), returned.get_sort())))
    return false;
  std::vector<z3::expr> arguments(inputs);
  arguments.insert(arguments.end(), carried.begin(), carried.end());
  if (!validArguments(continuation.ctx(), arguments))
    return false;
  for (std::size_t i = 0; i < carried.size(); ++i)
    if (&next[i].ctx() != &continuation.ctx() ||
        &initial[i].ctx() != &continuation.ctx() ||
        !z3::eq(next[i].get_sort(), carried[i].get_sort()) ||
        !z3::eq(initial[i].get_sort(), carried[i].get_sort()))
      return false;
  const auto functionName = name.empty() ? "recovered_loop" : std::string(name);
  if (module_->getFunction(functionName))
    return false;
  std::vector<llvm::Type *> types;
  for (const auto &arg: inputs)
    types.push_back(llvm::IntegerType::get(*ctx_, width(arg)));
  auto *fn = llvm::Function::Create(
          llvm::FunctionType::get(
                  llvm::IntegerType::get(*ctx_, width(returned)), types, false),
          llvm::GlobalValue::ExternalLinkage, functionName, *module_);
  const auto fail = [&]() {
    fn->eraseFromParent();
    return false;
  };
  auto *entry = llvm::BasicBlock::Create(*ctx_, "entry", fn);
  auto *preheader =
          entryGuard ? llvm::BasicBlock::Create(*ctx_, "loop.preheader", fn)
                     : entry;
  auto *header = llvm::BasicBlock::Create(*ctx_, "loop.header", fn);
  auto *body = llvm::BasicBlock::Create(*ctx_, "loop.body", fn);
  auto *exit = llvm::BasicBlock::Create(*ctx_, "loop.exit", fn);
  llvm::IRBuilder<> b(entry);
  Values inputValues;
  for (std::size_t i = 0; i < inputs.size(); ++i) {
    // Z3 inputs are concrete bit-vector values, never LLVM undef/poison.
    // State this contract at the boundary rather than retaining freeze noise.
    fn->getArg(i)->addAttr(llvm::Attribute::NoUndef);
    fn->getArg(i)->setName(inputs[i].decl().name().str());
    inputValues.emplace(inputs[i].id(), fn->getArg(i));
  }
  if (entryGuard) {
    auto guardValues = inputValues;
    auto *guard = lowerExpression(*ctx_, b, guardValues, *entryGuard);
    if (!guard)
      return fail();
    auto *shortPath = llvm::BasicBlock::Create(*ctx_, "entry.otherwise", fn);
    b.CreateCondBr(guard, preheader, shortPath);
    b.SetInsertPoint(shortPath);
    auto shortValues = inputValues;
    auto *value = lowerExpression(*ctx_, b, shortValues, *otherwise);
    if (!value)
      return fail();
    b.CreateRet(value);
    b.SetInsertPoint(preheader);
  }
  std::vector<llvm::Value *> seeds;
  auto seedValues = inputValues;
  for (const auto &expression: initial) {
    auto *value = lowerExpression(*ctx_, b, seedValues, expression);
    if (!value)
      return fail();
    seeds.push_back(value);
  }
  b.CreateBr(header);
  b.SetInsertPoint(header);
  auto headerValues = inputValues;
  std::vector<llvm::PHINode *> phis;
  for (std::size_t i = 0; i < carried.size(); ++i) {
    auto *phi = b.CreatePHI(llvm::IntegerType::get(*ctx_, width(carried[i])), 2,
                            carried[i].decl().name().str());
    phi->addIncoming(seeds[i], preheader);
    phis.push_back(phi);
    headerValues.emplace(carried[i].id(), phi);
  }
  auto *condition = lowerExpression(*ctx_, b, headerValues, continuation);
  if (!condition)
    return fail();
  b.CreateCondBr(condition, body, exit);
  b.SetInsertPoint(body);
  auto bodyValues = headerValues;
  std::vector<llvm::Value *> updates;
  for (const auto &expression: next) {
    auto *value = lowerExpression(*ctx_, b, bodyValues, expression);
    if (!value)
      return fail();
    updates.push_back(value);
  }
  for (std::size_t i = 0; i < phis.size(); ++i)
    phis[i]->addIncoming(updates[i], body);
  b.CreateBr(header);
  b.SetInsertPoint(exit);
  // Body values do not dominate the exit; only header values may be reused.
  auto exitValues = headerValues;
  auto *value = lowerExpression(*ctx_, b, exitValues, returned);
  if (!value)
    return fail();
  b.CreateRet(value);
  if (llvm::verifyFunction(*fn))
    return fail();
  return true;
}

bool dragon::llvmlifter::LLVMLifter::liftEffects(
        const z3::expr *expression, const std::vector<z3::expr> &arguments,
        const std::vector<bool> &pointerArguments,
        const ignil::MemoryEffects &effects, std::string_view name) {
  if (!effects.valid() || arch_ != Architecture::X86_64 ||
      pointerArguments.size() != arguments.size() ||
      !validArguments(effects.initial().ctx(), arguments) ||
      (expression && (&expression->ctx() != &effects.initial().ctx() ||
                      !width(*expression) || width(*expression) > 4096)))
    return false;
  std::vector<llvm::Type *> types;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    if (pointerArguments[i] &&
        (!arguments[i].is_bv() || width(arguments[i]) != 64))
      return false;
    types.push_back(
            pointerArguments[i]
                    ? static_cast<llvm::Type *>(
                              llvm::PointerType::getUnqual(*ctx_))
                    : llvm::IntegerType::get(*ctx_, width(arguments[i])));
  }
  auto *resultType = expression
                             ? static_cast<llvm::Type *>(llvm::IntegerType::get(
                                       *ctx_, width(*expression)))
                             : llvm::Type::getVoidTy(*ctx_);
  auto *fn = llvm::Function::Create(
          llvm::FunctionType::get(resultType, types, false),
          llvm::GlobalValue::ExternalLinkage,
          name.empty() ? "recovered" : std::string(name), *module_);
  llvm::IRBuilder<> b(llvm::BasicBlock::Create(*ctx_, "entry", fn));
  Values values;
  for (std::size_t i = 0; i < arguments.size(); ++i) {
    auto *arg = fn->getArg(i);
    arg->setName(arguments[i].decl().name().str());
    values.emplace(arguments[i].id(),
                   pointerArguments[i] ? b.CreatePtrToInt(arg, b.getInt64Ty())
                                       : static_cast<llvm::Value *>(arg));
  }
  auto fail = [&]() {
    fn->eraseFromParent();
    return false;
  };
  for (const auto &event: effects.events()) {
    auto *address = lowerExpression(*ctx_, b, values, event.address);
    if (!address || !address->getType()->isIntegerTy(64))
      return fail();
    auto *pointer = b.CreateIntToPtr(address, b.getPtrTy());
    if (event.isStore) {
      auto *value = lowerExpression(*ctx_, b, values, event.value);
      if (!value)
        return fail();
      b.CreateAlignedStore(value, pointer, llvm::Align(1));
    } else {
      // The original load remains at its actual point in the event stream.
      // Later address/value DAGs see its runtime value, never captured bytes.
      if (values.contains(event.value.id()))
        return fail();
      auto *value =
              b.CreateAlignedLoad(llvm::IntegerType::get(*ctx_, event.width),
                                  pointer, llvm::Align(1));
      values.emplace(event.value.id(), value);
    }
  }
  if (expression) {
    auto *value = lowerExpression(*ctx_, b, values, *expression);
    if (!value)
      return fail();
    b.CreateRet(value);
  } else
    b.CreateRetVoid();
  if (llvm::verifyFunction(*fn))
    return fail();
  // Explicit little-endian flat 64-bit layout, matching the source memory
  // model.
  module_->setDataLayout("e-p:64:64-i64:64-n8:16:32:64-S128");
  return true;
}
