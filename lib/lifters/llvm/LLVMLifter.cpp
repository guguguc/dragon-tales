#include <dragon/lifters/llvm/LLVMLifter.hpp>

#include <dragon/analysis/ArgumentRecovery.hpp>
#include <dragon/lifters/ignil/x86/x86IGNILRegs.hpp>

#include <format>
#include <utility>

#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/Analysis/LoopAnalysisManager.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar/DCE.h>
#include <llvm/Transforms/Scalar/GVN.h>
#include <llvm/Transforms/Utils/Mem2Reg.h>

bool dragon::llvmlifter::LLVMLifter::lift(const Function &fn,
                                          const Graph &graph) {
  // Refuse an invalid Function view rather than crash on it. Function's
  // constructor already defines what that means - not a known valid
  // function, no blocks, or an invalid block inside it - lift() simply
  // never checked. (Checking blocks().empty() instead would miss the
  // bad-block case, where blocks_ is partially filled but valid_ is false.)
  //
  // A blockless function is not exotic: discoverFunctionStarts() trusts
  // every call target unconditionally, so a call to an address outside the
  // disassembled range - an ordinary PLT stub reached from a raw .text
  // blob - becomes a function start with nothing under it. Graph::functions()
  // filters those out via isValid(), but a Function can also be built
  // directly from an address, which is exactly what the C shim's
  // dragon_graph_get_function() does - so every C and Python caller can
  // reach one.
  //
  // buildBlockMap() below cannot catch this: it only reports a missing
  // IGNIL block from inside its per-block loop, so with zero blocks it
  // returns an empty but perfectly valid map and that guard passes
  // vacuously - after which buildRegFile() -> allocateRegFile() reads
  // llfn->getEntryBlock() on a function with no basic blocks, and
  // segfaults. Checked before the llvm::Function is created, so a rejected
  // lift leaves nothing behind in the module.
  if (!fn.isValid())
    return false;

  // Generate a function without return value, and without parameters
  // we have not extracted information about that yet...
  // The name is the address of the function.
  std::string name = std::format("sub_{:x}", fn.startAddress());
  auto *ptrTy = llvm::PointerType::getUnqual(*ctx_);
  auto *voidTy = llvm::Type::getVoidTy(*ctx_);
  auto *FnType = llvm::FunctionType::get(voidTy, {ptrTy, ptrTy}, false);
  auto *llfn = llvm::Function::Create(
          FnType, llvm::GlobalValue::ExternalLinkage, name, *module_);
  llfn->getArg(0)->setName("mem");
  llfn->getArg(1)->setName("regs");

  // Record the recovered prototype as a function attribute: non-destructive,
  // survives the optimisation passes, and is greppable in the printed IR
  // (`"dragon.signature"="i32 sub_1000(i32 RDI, ...)"`). The body still uses
  // the (mem, regs) convention; turning this signature into a real typed
  // FunctionType - with the arguments seeded from LLVM parameters and a
  // modelled stack replacing the mem pointer - is the next step (see
  // ToDo/Roadmap.md).
  llfn->addFnAttr(
          "dragon.signature",
          analysis::toString(analysis::recoverSignature(fn, graph, arch_),
                             fn.startAddress()));

  auto *memPtr  = llfn->getArg(0);
  auto *regsPtr = llfn->getArg(1);

  auto bbMap = buildBlockMap(llfn, &fn, graph);

  if (!bbMap)
    return false;

  auto regFile = buildRegFile(llfn, &fn, graph);

  initializeRegistersFromParam(llfn, regFile, regsPtr);

  for (const auto &[addr, block]: fn.blocks()) {
    const auto *ib = graph.getIGNILBlock(addr);
    if (!ib)
      continue;
    TempMap temps{}; // fresh per block - Temp ids don't cross block boundaries
    liftBlock(ib, llfn, &regFile, &temps, memPtr, regsPtr, bbMap.value());
  }
  return true;
}
void dragon::llvmlifter::LLVMLifter::collectRegsFromOps(
        const std::vector<ignil::Op> &ops, RegFile &regFile,
        std::map<std::pair<std::uint32_t, ignil::Width>, std::string_view>
                &regNames) const {
  // Lambda used to check if a value contains a register.
  // in that case, we will keep it for the alloca instruction
  auto collect = [&](const ignil::Value &v) {
    if (std::holds_alternative<ignil::Reg>(v)) {
      const auto &reg = std::get<ignil::Reg>(v);
      regFile[reg.offset].try_emplace(reg.width, nullptr);
      if (!reg.name.empty())
        regNames[{reg.offset, reg.width}] = reg.name;
    }
  };

  // x86-64: a write to a 32-bit general-purpose register clears the upper half
  // of its 64-bit parent. mergeIntoParent() does that - but only into a parent
  // slot that exists, and slots are made for the widths the code mentions. A
  // function that only ever says `eax` would have no RAX slot, so nothing
  // would be zero-extended and only 32 bits would be written back on return:
  // the caller's upper half of RAX would survive `xor eax, eax`. Give every
  // such destination its parent.
  constexpr std::uint32_t kX86GprSpaceEnd = 128; // RAX..R15, 8 bytes each
  auto collectParent = [&](const ignil::Value &v) {
    if (arch_ != Architecture::X86_64)
      return;
    const auto *reg = std::get_if<ignil::Reg>(&v);
    if (reg && reg->width == 32 && reg->offset < kX86GprSpaceEnd &&
        reg->offset % 8 == 0)
      regFile[reg->offset].try_emplace(64, nullptr);
  };

  for (const auto &op: ops) {
    if (op.dst.has_value()) {
      collect(op.dst.value());
      collectParent(op.dst.value());
    }
    for (const auto &src: op.srcs)
      collect(src);
  }
}

void dragon::llvmlifter::LLVMLifter::allocateRegFile(
        llvm::Function *llfn, RegFile &regFile,
        const std::map<std::pair<std::uint32_t, ignil::Width>,
                       std::string_view> &regNames) const {
  llvm::IRBuilder<> builder(&llfn->getEntryBlock(),
                            llfn->getEntryBlock().begin());
  for (auto &[offset, widthMap]: regFile) {
    for (auto &[width, slot]: widthMap) {
      // If we can provide a better naming...s
      auto it = regNames.find({offset, width});
      std::string name = (it != regNames.end())
                                 ? std::string(it->second)
                                 : "reg_" + std::to_string(offset) + "_" +
                                           std::to_string(width) + "b";
      slot = builder.CreateAlloca(llvm::IntegerType::get(*ctx_, width), nullptr,
                                  name);
    }
  }
}

dragon::llvmlifter::LLVMLifter::RegFile
dragon::llvmlifter::LLVMLifter::buildRegFile(llvm::Function *llfn,
                                             const Function *fn,
                                             const Graph &graph) const {
  RegFile regFile{};
  std::map<std::pair<uint32_t, ignil::Width>, std::string_view> regNames;

  // go through every block of the function
  for (const auto &[addr, block]: fn->blocks()) {
    // retrieve the lifted version
    const auto *ignilBlock = graph.getIGNILBlock(addr);
    if (!ignilBlock)
      continue;
    collectRegsFromOps(ignilBlock->ops(), regFile, regNames);
  }

  allocateRegFile(llfn, regFile, regNames);
  return regFile;
}

bool dragon::llvmlifter::LLVMLifter::liftBlock(const ignil::Block &block,
                                               std::string_view name) {
  if (block.empty())
    return false;

  std::string fnName = name.empty() ? "trace" : std::string(name);
  auto *ptrTy = llvm::PointerType::getUnqual(*ctx_);
  auto *voidTy = llvm::Type::getVoidTy(*ctx_);
  auto *FnType = llvm::FunctionType::get(voidTy, {ptrTy, ptrTy}, false);
  auto *llfn = llvm::Function::Create(
          FnType, llvm::GlobalValue::ExternalLinkage, fnName, *module_);
  llfn->getArg(0)->setName("mem");
  llfn->getArg(1)->setName("regs");
  auto *memPtr  = llfn->getArg(0);
  auto *regsPtr = llfn->getArg(1);

  auto *entry = llvm::BasicBlock::Create(*ctx_, "entry", llfn);

  RegFile regFile{};
  std::map<std::pair<std::uint32_t, ignil::Width>, std::string_view> regNames;
  collectRegsFromOps(block.ops(), regFile, regNames);
  allocateRegFile(llfn, regFile, regNames);

  initializeRegistersFromParam(llfn, regFile, regsPtr);

  TempMap temps{};
  llvm::IRBuilder<> builder(entry);
  const std::map<std::uint64_t, llvm::BasicBlock *> noTargets;
  bool sawRet = false;

  for (const auto &op: block.ops()) {
    // A linear, already-resolved trace has nothing left to branch on - the
    // op sequence itself already *is* the path that was taken.
    if (op.opcode == ignil::Opcode::JMP || op.opcode == ignil::Opcode::CJMP)
      continue;
    liftOp(op, regFile, temps, memPtr, regsPtr, builder, noTargets);
    if (op.opcode == ignil::Opcode::RET) {
      sawRet = true;
      break; // liftOp's RET case already terminated the block
    }
  }

  if (!sawRet)
    emitReturn(regFile, regsPtr, builder);

  return true;
}
bool dragon::llvmlifter::LLVMLifter::liftPath(
        const std::vector<ResolvedPathStep> &steps, std::string_view name) {
  using Transfer = ResolvedPathStep::Transfer;
  if (arch_ != Architecture::X86_64 || steps.empty() ||
      steps.back().transfer != Transfer::Return)
    return false;
  // Validate before mutating the module. A body may end with one branch, but
  // calls/returns belong to the explicit transfer descriptor, never both.
  for (std::size_t i = 0; i < steps.size(); ++i) {
    const auto &step = steps[i];
    if (i + 1 < steps.size() && step.nextAddress != steps[i + 1].address)
      return false;
    if (step.transfer != Transfer::Next && step.transfer != Transfer::Call &&
        step.transfer != Transfer::Return)
      return false;
    if (step.stackAdjustment > 65535 ||
        (step.transfer != Transfer::Return && step.stackAdjustment != 0))
      return false;
    if (!step.body)
      continue;
    for (std::size_t j = 0; j < step.body->ops().size(); ++j) {
      auto opcode = step.body->ops()[j].opcode;
      if (opcode == ignil::Opcode::CALL || opcode == ignil::Opcode::RET)
        return false;
      if ((opcode == ignil::Opcode::JMP || opcode == ignil::Opcode::CJMP) &&
          (j + 1 != step.body->ops().size() || step.transfer != Transfer::Next))
        return false;
    }
  }
  auto *ptrTy = llvm::PointerType::getUnqual(*ctx_);
  auto *fty = llvm::FunctionType::get(llvm::Type::getVoidTy(*ctx_),
                                      {ptrTy, ptrTy}, false);
  auto *fn = llvm::Function::Create(
          fty, llvm::GlobalValue::ExternalLinkage,
          name.empty() ? "resolved_path" : std::string(name), *module_);
  fn->getArg(0)->setName("mem");
  fn->getArg(1)->setName("regs");
  fn->addFnAttr("dragon.path-specialized", "symbolically resolved edges");
  std::vector<llvm::BasicBlock *> blocks;
  for (std::size_t i = 0; i < steps.size(); ++i)
    blocks.push_back(llvm::BasicBlock::Create(
            *ctx_, std::format("path_{}_{:x}", i, steps[i].address), fn));

  RegFile regs;
  std::map<std::pair<std::uint32_t, ignil::Width>, std::string_view> names;
  for (const auto &step: steps)
    if (step.body)
      collectRegsFromOps(step.body->ops(), regs, names);
  // Transfer handling always observes the architectural stack pointer.
  regs[x86::kOffRSP].try_emplace(64, nullptr);
  names[{x86::kOffRSP, 64}] = "RSP";
  allocateRegFile(fn, regs, names);
  initializeRegistersFromParam(fn, regs, fn->getArg(1));
  const std::map<std::uint64_t, llvm::BasicBlock *> noTargets;
  for (std::size_t i = 0; i < steps.size(); ++i) {
    const auto &step = steps[i];
    llvm::IRBuilder<> builder(blocks[i]);
    TempMap temps; // Temp IDs are local even when a source PC repeats.
    if (step.body) {
      for (const auto &op: step.body->ops()) {
        if (op.opcode == ignil::Opcode::JMP ||
            op.opcode == ignil::Opcode::CJMP) {
          auto *target = resolve(op.srcs.at(0), regs, temps, builder);
          if (op.opcode == ignil::Opcode::CJMP) {
            auto *cond = target;
            if (cond->getType()->getIntegerBitWidth() != 1)
              cond = builder.CreateTrunc(cond, builder.getInt1Ty());
            target = builder.CreateSelect(
                    cond, resolve(op.srcs.at(1), regs, temps, builder),
                    resolve(op.srcs.at(2), regs, temps, builder));
          }
          builder.CreateAssumption(builder.CreateICmpEQ(
                  target,
                  llvm::ConstantInt::get(target->getType(), step.nextAddress)));
        } else {
          liftOp(op, regs, temps, fn->getArg(0), fn->getArg(1), builder,
                 noTargets);
        }
      }
    }
    if (step.transfer != Transfer::Next) {
      auto *sp = builder.CreateLoad(builder.getInt64Ty(),
                                    regs.at(x86::kOffRSP).at(64));
      llvm::Value *newSP;
      if (step.transfer == Transfer::Call) {
        newSP = builder.CreateSub(sp, builder.getInt64(8));
        auto *addr =
                builder.CreateGEP(builder.getInt8Ty(), fn->getArg(0), newSP);
        builder.CreateStore(builder.getInt64(step.returnAddress), addr)
                ->setAlignment(llvm::Align(1));
      } else {
        auto *addr = builder.CreateGEP(builder.getInt8Ty(), fn->getArg(0), sp);
        auto *target = builder.CreateLoad(builder.getInt64Ty(), addr);
        target->setAlignment(llvm::Align(1));
        builder.CreateAssumption(builder.CreateICmpEQ(
                target, builder.getInt64(step.nextAddress)));
        newSP = builder.CreateAdd(sp,
                                  builder.getInt64(8 + step.stackAdjustment));
      }
      builder.CreateStore(newSP, regs.at(x86::kOffRSP).at(64));
      mergeIntoParent(x86::kOffRSP, 64, newSP, regs, builder);
    }
    if (i + 1 == steps.size())
      emitReturn(regs, fn->getArg(1), builder);
    else
      builder.CreateBr(blocks[i + 1]);
  }
  return true;
}

std::optional<std::map<std::uint64_t, llvm::BasicBlock *>>
dragon::llvmlifter::LLVMLifter::buildBlockMap(llvm::Function *llfn,
                                              const Function *fn,
                                              const Graph &graph) const {
  std::map<std::uint64_t, llvm::BasicBlock *> addrBlock;

  for (const auto &[addr, block]: fn->blocks()) {
    // If a block cannot be obtained from IGNIL, it doesn't have
    // any sense to lift the function to LLVM IR, since a block
    // would be lost.
    if (!graph.getIGNILBlock(addr))
      return std::nullopt;

    addrBlock[addr] =
            llvm::BasicBlock::Create(*ctx_, "bb_" + std::to_string(addr), llfn);
  }

  return addrBlock;
}
void dragon::llvmlifter::LLVMLifter::liftBlock(
        const ignil::Block *ib, llvm::Function *llfn, RegFile *regs,
        TempMap *temps, llvm::Value *memPtr, llvm::Value *regsPtr,
        const std::map<std::uint64_t, llvm::BasicBlock *> &bbMap) {
  llvm::IRBuilder<> builder(bbMap.at(ib->startAddress()));

  for (const auto &op: ib->ops())
    liftOp(op, *regs, *temps, memPtr, regsPtr, builder, bbMap);
}
void dragon::llvmlifter::LLVMLifter::liftOp(
        const ignil::Op &op, RegFile &regs, TempMap &temps, llvm::Value *memPtr,
        llvm::Value *regsPtr, llvm::IRBuilder<> &builder,
        const std::map<std::uint64_t, llvm::BasicBlock *> &bbMap) {

  // Store a result into dst: Temp → SSA table, Reg → alloca + sub-reg merge.
  auto emit = [&](llvm::Value *val) {
    if (!op.dst)
      return;
    if (const auto *t = std::get_if<ignil::Temp>(&*op.dst)) {
      // If it is a temporal value, it will be used
      // for SSA
      temps[t->id] = val;
    } else if (const auto *r = std::get_if<ignil::Reg>(&*op.dst)) {
      auto *slotTy = llvm::IntegerType::get(*ctx_, r->width);
      if (val->getType()->isDoubleTy()) {
        // FADD/FSUB/FMUL/SITOFP produce a real `double`-typed value (kept
        // that way rather than laundered through i64 at every step so
        // Temp-to-Temp chains stay in LLVM's native float domain, giving
        // its own float-aware constant folding/InstCombine the best shot
        // at simplifying it) - reinterpret its bits back into the
        // register's integer slot, the same width-64-bits-either-way
        // reinterpretation every XMM Reg already models.
        val = builder.CreateBitCast(val, slotTy);
      } else if (val->getType() != slotTy) {
        val = builder.CreateZExt(val, slotTy);
      }
      builder.CreateStore(val, regs.at(r->offset).at(r->width));
      mergeIntoParent(r->offset, r->width, val, regs, builder);
    }
  };

  // Lambda functions to quickly manage the common operands of the operations
  auto r0 = [&] { return resolve(op.srcs[0], regs, temps, builder); };
  auto r1 = [&] { return resolve(op.srcs[1], regs, temps, builder); };
  auto r2 = [&] { return resolve(op.srcs[2], regs, temps, builder); };
  // Lambda to quickly retrieve the integer type of the destination
  auto dstTy = [&] {
    return llvm::IntegerType::get(*ctx_, ignil::widthOf(*op.dst));
  };
  // SHL/SHR/SAR's shift-count operand (srcs[1]) is narrower than the
  // shifted value on real ISAs (x86 shift-by-immediate/CL is always an
  // 8-bit count regardless of operand width) - IGNIL preserves that
  // narrower width, but LLVM's shift instructions require both operands to
  // share exactly one type. Normalize with zext/trunc before building the
  // instruction, or LLVM happily builds a type-mismatched shl/lshr/ashr
  // that only fails much later, when something tries to parse the printed
  // IR back in (verifier catches it too, but nothing here calls verify()).
  auto shiftAmt = [&](llvm::Value *lhs) {
    auto *rhs = r1();
    if (rhs->getType() != lhs->getType())
      rhs = builder.CreateZExtOrTrunc(rhs, lhs->getType());
    return rhs;
  };
  // FADD/FSUB/FMUL/FDIV/FPTOSI's operands are raw 64-bit slots (a Reg read,
  // a Const, or a Temp chained from an earlier integer op) that need
  // reinterpreting as `double` before real float arithmetic can run on
  // them - unless the value is already `double` (a Temp already produced
  // by a prior float op in the same chain), in which case it's used as-is
  // rather than round-tripped through another bitcast.
  auto asDouble = [&](llvm::Value *v) {
    return v->getType()->isDoubleTy()
                   ? v
                   : builder.CreateBitCast(v, builder.getDoubleTy());
  };
  // A 32-bit address is unsigned, but a GEP sign-extends its index.
  auto memAddress = [&](llvm::Value *addr) {
    auto *indexTy = module_->getDataLayout().getIndexType(memPtr->getType());
    return builder.CreateGEP(builder.getInt8Ty(), memPtr,
                             builder.CreateZExtOrBitCast(addr, indexTy));
  };

  switch (op.opcode) {
    // --- Data movement ---
    case ignil::Opcode::COPY:
      emit(r0());
      break;

    case ignil::Opcode::LOAD: {
      auto *load = builder.CreateLoad(dstTy(), memAddress(r0()));
      load->setAlignment(
              llvm::Align(1)); // x86 memory operands may be unaligned.
      emit(load);
      break;
    }
    case ignil::Opcode::STORE:
      builder.CreateStore(r1(), memAddress(r0()))->setAlignment(llvm::Align(1));
      break;

    // --- Arithmetic ---
    case ignil::Opcode::ADD:
      emit(builder.CreateAdd(r0(), r1()));
      break;
    case ignil::Opcode::SUB:
      emit(builder.CreateSub(r0(), r1()));
      break;
    case ignil::Opcode::NEG:
      emit(builder.CreateNeg(r0()));
      break;
    case ignil::Opcode::MUL:
      emit(builder.CreateMul(r0(), r1()));
      break;
    case ignil::Opcode::SDIV:
      emit(builder.CreateSDiv(r0(), r1()));
      break;
    case ignil::Opcode::UDIV:
      emit(builder.CreateUDiv(r0(), r1()));
      break;
    case ignil::Opcode::SMOD:
      emit(builder.CreateSRem(r0(), r1()));
      break;
    case ignil::Opcode::UMOD:
      emit(builder.CreateURem(r0(), r1()));
      break;

    // --- Floating-point (IEEE754 double) ---
    case ignil::Opcode::FADD:
      emit(builder.CreateFAdd(asDouble(r0()), asDouble(r1())));
      break;
    case ignil::Opcode::FSUB:
      emit(builder.CreateFSub(asDouble(r0()), asDouble(r1())));
      break;
    case ignil::Opcode::FMUL:
      emit(builder.CreateFMul(asDouble(r0()), asDouble(r1())));
      break;
    case ignil::Opcode::FDIV:
      emit(builder.CreateFDiv(asDouble(r0()), asDouble(r1())));
      break;

    // --- Bitwise ---
    case ignil::Opcode::AND:
      emit(builder.CreateAnd(r0(), r1()));
      break;
    case ignil::Opcode::OR:
      emit(builder.CreateOr(r0(), r1()));
      break;
    case ignil::Opcode::XOR:
      emit(builder.CreateXor(r0(), r1()));
      break;
    case ignil::Opcode::NOT:
      emit(builder.CreateNot(r0()));
      break;
    case ignil::Opcode::SHL: {
      auto *lhs = r0();
      emit(builder.CreateShl(lhs, shiftAmt(lhs)));
      break;
    }
    case ignil::Opcode::SHR: {
      auto *lhs = r0();
      emit(builder.CreateLShr(lhs, shiftAmt(lhs)));
      break;
    }
    case ignil::Opcode::SAR: {
      auto *lhs = r0();
      emit(builder.CreateAShr(lhs, shiftAmt(lhs)));
      break;
    }

    // --- Width conversions ---
    case ignil::Opcode::ZEXT:
      emit(builder.CreateZExt(r0(), dstTy()));
      break;
    case ignil::Opcode::SEXT:
      emit(builder.CreateSExt(r0(), dstTy()));
      break;
    case ignil::Opcode::TRUNC:
      emit(builder.CreateTrunc(r0(), dstTy()));
      break;

    // --- Int <-> float conversion ---
    case ignil::Opcode::SITOFP:
      emit(builder.CreateSIToFP(r0(), builder.getDoubleTy()));
      break;
    case ignil::Opcode::FPTOSI:
      emit(builder.CreateFPToSI(asDouble(r0()), dstTy()));
      break;

    // --- Comparisons (always produce i1) ---
    case ignil::Opcode::EQ:
      emit(builder.CreateICmpEQ(r0(), r1()));
      break;
    case ignil::Opcode::NEQ:
      emit(builder.CreateICmpNE(r0(), r1()));
      break;
    case ignil::Opcode::ULT:
      emit(builder.CreateICmpULT(r0(), r1()));
      break;
    case ignil::Opcode::ULE:
      emit(builder.CreateICmpULE(r0(), r1()));
      break;
    case ignil::Opcode::UGT:
      emit(builder.CreateICmpUGT(r0(), r1()));
      break;
    case ignil::Opcode::UGE:
      emit(builder.CreateICmpUGE(r0(), r1()));
      break;
    case ignil::Opcode::SLT:
      emit(builder.CreateICmpSLT(r0(), r1()));
      break;
    case ignil::Opcode::SLE:
      emit(builder.CreateICmpSLE(r0(), r1()));
      break;
    case ignil::Opcode::SGT:
      emit(builder.CreateICmpSGT(r0(), r1()));
      break;
    case ignil::Opcode::SGE:
      emit(builder.CreateICmpSGE(r0(), r1()));
      break;

    // --- Control flow ---
    case ignil::Opcode::JMP: {
      auto *target = r0();
      if (const auto *ci = llvm::dyn_cast<llvm::ConstantInt>(target)) {
        auto it = bbMap.find(ci->getZExtValue());
        if (it != bbMap.end()) {
          builder.CreateBr(it->second);
          break;
        }
      }
      builder.CreateUnreachable(); // indirect or out-of-function target
      break;
    }

    case ignil::Opcode::CJMP: {
      auto *cond = r0();
      auto *taken = r1();
      auto *fall = r2();
      const auto *takenCI = llvm::dyn_cast<llvm::ConstantInt>(taken);
      const auto *fallCI = llvm::dyn_cast<llvm::ConstantInt>(fall);
      if (takenCI && fallCI) {
        auto takenIt = bbMap.find(takenCI->getZExtValue());
        auto fallIt = bbMap.find(fallCI->getZExtValue());
        if (takenIt != bbMap.end() && fallIt != bbMap.end()) {
          // Flag regs are i8 (0/1); LLVM br requires i1
          if (cond->getType()->getIntegerBitWidth() != 1)
            cond = builder.CreateTrunc(cond, builder.getInt1Ty());
          builder.CreateCondBr(cond, takenIt->second, fallIt->second);
          break;
        }
      }
      builder.CreateUnreachable();
      break;
    }

    case ignil::Opcode::CALL: {
      auto *ptrTy = llvm::PointerType::getUnqual(*ctx_);
      auto *fnTy = llvm::FunctionType::get(llvm::Type::getVoidTy(*ctx_),
                                           {ptrTy}, false);
      auto *target = r0();
      llvm::Value *callee;
      if (const auto *ci = llvm::dyn_cast<llvm::ConstantInt>(target)) {
        callee =
                module_->getOrInsertFunction(
                               std::format("fn_{:x}", ci->getZExtValue()), fnTy)
                        .getCallee();
      } else {
        callee = builder.CreateIntToPtr(target, ptrTy); // indirect call
      }
      builder.CreateCall(fnTy, callee, {memPtr});
      break;
    }

    case ignil::Opcode::RET:
      emitReturn(regs, regsPtr, builder);
      break;

    case ignil::Opcode::UNDEF:
      if (op.dst)
        emit(llvm::UndefValue::get(dstTy()));
      break;

    // An instruction x86 defines but IGNIL cannot express, lowered the way
    // every lifter models an intrinsic: a call to a declared-but-never-defined
    // function. `readnone` lets LLVM CSE two calls that agree, which is
    // exactly right for CPUID and exactly wrong for RDTSC - so an impure kind
    // gets a name carrying its own address instead, making each site a
    // distinct function that nothing can fold together.
    case ignil::Opcode::OPAQUE: {
      if (!op.dst)
        break;
      const auto kind = ignil::opaqueKindOf(op.aux);
      std::string name = "dragon.opaque." +
                         std::string(ignil::opaqueKindName(kind)) + "." +
                         std::to_string(ignil::opaqueIndexOf(op.aux));
      if (!ignil::opaqueIsPure(kind))
        name += std::format(".at{:x}", op.address);

      std::vector<llvm::Value *> args;
      std::vector<llvm::Type *> argTys;
      args.reserve(op.srcs.size());
      argTys.reserve(op.srcs.size());
      for (const auto &src: op.srcs) {
        args.push_back(resolve(src, regs, temps, builder));
        argTys.push_back(args.back()->getType());
      }

      auto *fty = llvm::FunctionType::get(dstTy(), argTys, /*isVarArg=*/false);
      auto callee = module_->getOrInsertFunction(name, fty);
      if (auto *fn = llvm::dyn_cast<llvm::Function>(callee.getCallee())) {
        fn->setDoesNotAccessMemory();
        fn->setDoesNotThrow();
      }
      emit(builder.CreateCall(callee, args));
      break;
    }
  }
}

void dragon::llvmlifter::LLVMLifter::emitReturn(RegFile &regs,
                                                llvm::Value *regsPtr,
                                                llvm::IRBuilder<> &builder) {
  // Write back the widest register at each offset so callers can observe
  // the final register state even after aggressive optimisation passes.
  for (auto &[offset, widthMap]: regs) {
    auto &[width, slot] = *widthMap.rbegin(); // widest at this offset
    auto *ty  = llvm::IntegerType::get(*ctx_, width);
    auto *val = builder.CreateLoad(ty, slot);
    auto *ptr = builder.CreateGEP(builder.getInt8Ty(), regsPtr,
                                  builder.getInt32(offset));
    builder.CreateStore(val, ptr);
  }
  builder.CreateRetVoid();
}

llvm::Value *
dragon::llvmlifter::LLVMLifter::resolve(const ignil::Value &v, RegFile &regs,
                                        const TempMap &temps,
                                        llvm::IRBuilder<> &builder) const {

  // Check if it is a constant, in that case, generate
  // a constant llvm value width specific width and value.
  //
  // Defensively mask to `c->width` bits first: some X86IGNILLifter operand
  // decoding paths sign-extend an immediate to a full 64-bit pattern (e.g.
  // `cmp eax, 0xFFFFFFFF` produces Const{width=32,
  // value=0xFFFFFFFFFFFFFFFF}) without masking it back down to the
  // declared width. llvm::APInt's constructor asserts (in an
  // assertions-enabled build only - NDEBUG builds silently truncate) that
  // the value fits in `BitWidth` unsigned bits, so an unmasked over-wide
  // value here crashes any assertions-enabled build. Masking here is a
  // narrow, defensive fix at this one choke point (every ignil::Const
  // passes through here) - it does not fix the upstream sign-extension
  // bug itself, which is still real and worth root-causing (see
  // ToDo/Roadmap.md).
  if (const auto *c = std::get_if<ignil::Const>(&v)) {
    std::uint64_t masked = c->width >= 64
                                   ? c->value
                                   : c->value & ((std::uint64_t{1} << c->width) - 1);
    return llvm::ConstantInt::get(*ctx_, llvm::APInt(c->width, masked));
  }

  // Check if it is an existing register, in that case
  // we need to create a load
  if (const auto *r = std::get_if<ignil::Reg>(&v)) {
    auto *mem = regs.at(r->offset).at(r->width);
    return builder.CreateLoad(llvm::IntegerType::get(*ctx_, r->width), mem);
  }

  const auto &t = std::get<ignil::Temp>(v);
  return temps.at(t.id);
}
void dragon::llvmlifter::LLVMLifter::mergeIntoParent(
        std::uint32_t offset, ignil::Width width, llvm::Value *value,
        RegFile &regs, llvm::IRBuilder<> &builder) {
  auto it = regs.find(offset);
  if (it == regs.end())
    return;

  for (auto &[bigWidth, slot]: it->second) {
    if (bigWidth == width)
      continue;

    // A narrower slot is the low bits of the new value (`mov ecx, 0xffff`
    // then `inc cx` must read CX = 0xffff, not the stale CX slot).
    if (bigWidth < width) {
      builder.CreateStore(
              builder.CreateTrunc(value, llvm::IntegerType::get(*ctx_, bigWidth)),
              slot);
      continue;
    }

    auto *bigTy = llvm::IntegerType::get(*ctx_, bigWidth);

    // x86-64: writing a 32-bit register implicitly zero-extends into the
    // full 64-bit register (e.g. `mov ecx, 1` clears bits 32-63 of RCX) -
    // unlike 8/16-bit sub-register writes (AL, AX, ...), which leave the
    // rest of the register untouched. Every other width transition here
    // preserves the untouched high bits; this one specific transition must
    // not, or a register zeroed via its 32-bit name (a very common x86-64
    // idiom, e.g. `xor ecx, ecx`) would keep stale high bits when read back
    // through its 64-bit name.
    if (arch_ == Architecture::X86_64 && width == 32 && bigWidth == 64) {
      builder.CreateStore(builder.CreateZExt(value, bigTy), slot);
      continue;
    }

    auto *mask = llvm::ConstantInt::get(
            bigTy, ~llvm::APInt::getLowBitsSet(bigWidth, width));
    auto *parent = builder.CreateLoad(bigTy, slot);
    auto *cleared = builder.CreateAnd(parent, mask);
    auto *ext = builder.CreateZExt(value, bigTy);
    builder.CreateStore(builder.CreateOr(cleared, ext), slot);
  }
}

void dragon::llvmlifter::LLVMLifter::initializeRegistersFromParam(
        llvm::Function *llfn, RegFile &regFile, llvm::Value *regsPtr) {
  auto &entryBB = llfn->getEntryBlock();
  auto insertPt = entryBB.begin();
  while (insertPt != entryBB.end() && llvm::isa<llvm::AllocaInst>(*insertPt))
    ++insertPt;
  llvm::IRBuilder<> builder(&entryBB, insertPt);

  for (auto &[offset, widthMap] : regFile) {
    auto &[bigWidth, bigSlot] = *widthMap.rbegin();
    auto *bigTy = llvm::IntegerType::get(*ctx_, bigWidth);
    auto *ptr   = builder.CreateGEP(builder.getInt8Ty(), regsPtr,
                                    builder.getInt32(offset));
    auto *val   = builder.CreateLoad(bigTy, ptr);
    builder.CreateStore(val, bigSlot);
    for (auto &[width, slot] : widthMap) {
      if (width == bigWidth)
        continue;
      builder.CreateStore(
              builder.CreateTrunc(val, llvm::IntegerType::get(*ctx_, width)),
              slot);
    }
  }
}

// --- Constructor / destructor ---

dragon::llvmlifter::LLVMLifter::LLVMLifter(Architecture arch,
                                           std::string_view moduleName) :
    arch_(arch), ctx_(std::make_unique<llvm::LLVMContext>()),
    module_(std::make_unique<llvm::Module>(moduleName, *ctx_)) {}

dragon::llvmlifter::LLVMLifter::~LLVMLifter() = default;

dragon::llvmlifter::LLVMLifter::LLVMLifter(LLVMLifter &&) noexcept = default;

// --- Optimization passes ---

// Shared boilerplate: run a FunctionPassManager over every non-declaration
// function in the module.
static void runFPM(llvm::Module &mod, llvm::FunctionPassManager fpm) {
  llvm::LoopAnalysisManager lam;
  llvm::FunctionAnalysisManager fam;
  llvm::CGSCCAnalysisManager cgam;
  llvm::ModuleAnalysisManager mam;
  llvm::PassBuilder pb;
  pb.registerModuleAnalyses(mam);
  pb.registerCGSCCAnalyses(cgam);
  pb.registerFunctionAnalyses(fam);
  pb.registerLoopAnalyses(lam);
  pb.crossRegisterProxies(lam, fam, cgam, mam);
  llvm::ModulePassManager mpm;
  mpm.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(fpm)));
  mpm.run(mod, mam);
}

void dragon::llvmlifter::LLVMLifter::runMem2Reg() {
  llvm::FunctionPassManager fpm;
  fpm.addPass(llvm::PromotePass());
  runFPM(*module_, std::move(fpm));
}

void dragon::llvmlifter::LLVMLifter::runInstCombine() {
  llvm::FunctionPassManager fpm;
  fpm.addPass(llvm::InstCombinePass());
  runFPM(*module_, std::move(fpm));
}

void dragon::llvmlifter::LLVMLifter::runGVN() {
  llvm::FunctionPassManager fpm;
  fpm.addPass(llvm::GVNPass());
  runFPM(*module_, std::move(fpm));
}

void dragon::llvmlifter::LLVMLifter::runDCE() {
  llvm::FunctionPassManager fpm;
  fpm.addPass(llvm::DCEPass());
  runFPM(*module_, std::move(fpm));
}

// --- Accessors ---

std::string dragon::llvmlifter::LLVMLifter::ir() const {
  std::string out;
  llvm::raw_string_ostream os(out);
  module_->print(os, nullptr);
  return out;
}

llvm::Module &dragon::llvmlifter::LLVMLifter::module() { return *module_; }

std::string dragon::llvmlifter::LLVMLifter::recoveredSignatureString(
        const Function &fn, const Graph &graph) const {
  return analysis::toString(analysis::recoverSignature(fn, graph, arch_),
                            fn.startAddress());
}
