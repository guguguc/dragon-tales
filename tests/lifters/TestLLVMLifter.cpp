#include <catch2/catch_test_macros.hpp>

#include <dragon/disassembler/Disassembler.hpp>
#include <dragon/disassembler/Graph.hpp>
#include <dragon/lifters/llvm/LLVMLifter.hpp>

#include <llvm/IR/Verifier.h>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <vector>

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

static const dragon::Function *findFunction(
        const std::vector<dragon::Function> &fns, std::uint64_t addr) {
  auto it = std::find_if(fns.begin(), fns.end(),
                         [addr](const dragon::Function &f) {
                           return f.startAddress() == addr;
                         });
  return it == fns.end() ? nullptr : &*it;
}

// -----------------------------------------------------------------------
// Regression: a discovered function start with no blocks
// -----------------------------------------------------------------------

TEST_CASE("LLVMLifter - lift() refuses a function with no blocks",
          "[llvm][lifter]") {
  // call 0x0     e8 fb ef ff ff   (rel32 = -0x1005, target outside the range)
  // ret          c3
  //
  // Byte sequence verified with:
  //   objdump -D -b binary -m i386:x86-64 -M intel --adjust-vma=0x1000
  //
  // Call targets are trusted as function starts unconditionally, so 0x0
  // becomes a discovered function with zero blocks - the ordinary shape of
  // a PLT stub reached from a raw .text blob, not a contrived input. lift()
  // used to segfault on exactly this: buildBlockMap()'s "missing IGNIL
  // block" guard only fires from inside its per-block loop, so a blockless
  // function passed it vacuously and then read llfn->getEntryBlock() on a
  // function with no basic blocks. lift() now rejects any invalid Function
  // view up front.
  const std::vector<std::uint8_t> bytes = {0xE8, 0xFB, 0xEF, 0xFF, 0xFF, 0xC3};

  dragon::Configuration cfg;
  cfg.disassemblyStrategy = dragon::DisassemblyStrategy::LINEAR_SWEEP;
  cfg.syntax = dragon::Syntax::INTEL;

  dragon::Disassembler dis(dragon::Architecture::X86_64, cfg);
  dragon::Graph g(dragon::Architecture::X86_64, cfg);
  dis.disassemble(bytes, 0x1000, g);

  // 0x0 is a discovered function start (call targets are trusted
  // unconditionally) but has no blocks, so its Function view reports
  // itself invalid - exactly what the constructor documents.
  //
  // Built directly rather than via Graph::functions(), which filters
  // invalid views out. That filter is why a C++ caller iterating
  // functions() never saw this; the C shim's dragon_graph_get_function()
  // has no such filter, so C and Python callers reach it directly.
  const dragon::Function blockless(&g, 0x0);
  REQUIRE(g.isValidFunction(0x0));
  REQUIRE(blockless.blocks().empty());
  REQUIRE_FALSE(blockless.isValid());

  dragon::llvmlifter::LLVMLifter llvml{dragon::Architecture::X86_64,
                                       "blockless"};

  // Refused, not crashed - and nothing is left behind in the module.
  REQUIRE_FALSE(llvml.lift(blockless, g));
  REQUIRE(llvml.ir().find("sub_0") == std::string::npos);

  // The real function beside it still lifts, on the same lifter instance.
  const auto funcs = g.functions();
  const dragon::Function *real = findFunction(funcs, 0x1000);
  REQUIRE(real != nullptr);
  REQUIRE(real->isValid());
  REQUIRE(llvml.lift(*real, g));
}

static std::optional<dragon::Function>
disassembleI386(const std::vector<std::uint8_t> &bytes, dragon::Graph &g) {
  dragon::Configuration cfg;
  cfg.disassemblyStrategy = dragon::DisassemblyStrategy::LINEAR_SWEEP;
  dragon::Disassembler dis(dragon::Architecture::X86_32, cfg);
  dis.disassemble(bytes, 0x1000, g);
  const auto funcs = g.functions();
  if (const dragon::Function *fn = findFunction(funcs, 0x1000))
    return *fn;
  return std::nullopt;
}

TEST_CASE("LLVMLifter - i386 addresses are zero-extended", "[llvm][lifter]") {
  // mov eax, [ebx]; ret
  const std::vector<std::uint8_t> bytes = {0x8b, 0x03, 0xc3};
  dragon::Graph g(dragon::Architecture::X86_32, dragon::Configuration{});
  const auto fn = disassembleI386(bytes, g);
  REQUIRE(fn);

  dragon::llvmlifter::LLVMLifter llvml{dragon::Architecture::X86_32};
  REQUIRE(llvml.lift(*fn, g));
  REQUIRE_FALSE(llvm::verifyModule(llvml.module(), &llvm::errs()));
  // A sign-extended index would put [0x80000000] 2 GB below the memory base.
  const std::string ir = llvml.ir();
  REQUIRE(ir.find("zext i32") != std::string::npos);
  REQUIRE(ir.find("sext") == std::string::npos);
}

TEST_CASE("LLVMLifter - an indirect call is through a pointer",
          "[llvm][lifter]") {
  // call edx; ret
  const std::vector<std::uint8_t> bytes = {0xff, 0xd2, 0xc3};
  dragon::Graph g(dragon::Architecture::X86_32, dragon::Configuration{});
  const auto fn = disassembleI386(bytes, g);
  REQUIRE(fn);

  dragon::llvmlifter::LLVMLifter llvml{dragon::Architecture::X86_32};
  REQUIRE(llvml.lift(*fn, g));
  REQUIRE_FALSE(llvm::verifyModule(llvml.module(), &llvm::errs()));
}

TEST_CASE("LLVMLifter - resolved path validates contexts before mutation",
          "[llvm][lifter][path]") {
  using Step = dragon::llvmlifter::ResolvedPathStep;
  dragon::llvmlifter::LLVMLifter ll(dragon::Architecture::X86_64);
  REQUIRE_FALSE(ll.liftPath({}));
  REQUIRE_FALSE(ll.liftPath({{nullptr, 0x1000, 0x6000, Step::Transfer::Next}}));
  REQUIRE_FALSE(
          ll.liftPath({{nullptr, 0x1000, 0x1010, Step::Transfer::Call, 0x1005},
                       {nullptr, 0x1020, 0x6000, Step::Transfer::Return}}));
  REQUIRE_FALSE(ll.liftPath(
          {{nullptr, 0x1000, 0x6000, Step::Transfer::Return, 0, 65536}}));
  dragon::ignil::Block premature(0x1000);
  premature.append({dragon::ignil::Opcode::RET, std::nullopt, {}, 0x1000});
  REQUIRE_FALSE(
          ll.liftPath({{&premature, 0x1000, 0x6000, Step::Transfer::Return}}));
  REQUIRE(ll.module().empty());
}

TEST_CASE(
        "LLVMLifter - resolved calls and returns are inlined with stack guards",
        "[llvm][lifter][path]") {
  using Step = dragon::llvmlifter::ResolvedPathStep;
  dragon::llvmlifter::LLVMLifter ll(dragon::Architecture::X86_64);
  REQUIRE(ll.liftPath({{nullptr, 0x1000, 0x1010, Step::Transfer::Call, 0x1005},
                       {nullptr, 0x1010, 0x1005, Step::Transfer::Return},
                       {nullptr, 0x1005, 0x6000, Step::Transfer::Return}},
                      "inlined"));
  REQUIRE_FALSE(llvm::verifyModule(ll.module()));
  auto ir = ll.ir();
  REQUIRE(ir.find("path_0_1000") != std::string::npos);
  REQUIRE(ir.find("path_1_1010") != std::string::npos);
  REQUIRE(ir.find("path_2_1005") != std::string::npos);
  REQUIRE(ir.find("@llvm.assume") != std::string::npos);
  REQUIRE(ir.find("@fn_") == std::string::npos);
  ll.runMem2Reg();
  ll.runInstCombine();
  ll.runGVN();
  ll.runDCE();
  REQUIRE_FALSE(llvm::verifyModule(ll.module()));
}

TEST_CASE("LLVMLifter - repeated source PCs have independent temp scopes",
          "[llvm][lifter][path]") {
  using namespace dragon::ignil;
  using Step = dragon::llvmlifter::ResolvedPathStep;
  Block body(0x1000);
  body.append({Opcode::ADD,
               Value{Temp{1, 32}},
               {Reg{0, 32, "EAX"}, Const{1, 32}},
               0x1000});
  body.append({Opcode::COPY, Value{Reg{0, 32, "EAX"}}, {Temp{1, 32}}, 0x1000});
  body.append({Opcode::JMP, std::nullopt, {Const{0x1000, 64}}, 0x1002});
  dragon::llvmlifter::LLVMLifter ll(dragon::Architecture::X86_64);
  REQUIRE(ll.liftPath({{&body, 0x1000, 0x1000, Step::Transfer::Next},
                       {&body, 0x1000, 0x1000, Step::Transfer::Next},
                       {nullptr, 0x1000, 0x6000, Step::Transfer::Return}}));
  REQUIRE_FALSE(llvm::verifyModule(ll.module()));
  REQUIRE(ll.ir().find("path_1_1000") != std::string::npos);
  ll.runMem2Reg();
  ll.runInstCombine();
  ll.runGVN();
  ll.runDCE();
  REQUIRE_FALSE(llvm::verifyModule(ll.module()));
}

#ifdef DRAGON_WITH_Z3
#include <z3++.h>

TEST_CASE("LLVMLifter - recovered expression is typed and algorithm independent",
          "[llvm][lifter][expression]") {
  z3::context ctx;
  auto a = ctx.bv_const("a", 32), b = ctx.bv_const("b", 32);
  dragon::llvmlifter::LLVMLifter ll(dragon::Architecture::X86_64);
  auto expression = (a * ctx.bv_val(7, 32)) ^ b;
  REQUIRE(ll.liftExpression(expression, {a, b}, "not_add"));
  REQUIRE_FALSE(llvm::verifyModule(ll.module()));
  ll.runInstCombine();
  ll.runDCE();
  auto ir = ll.ir();
  REQUIRE(ir.find("define i32 @not_add(i32 noundef %a, i32 noundef %b)") != std::string::npos);
  REQUIRE(ir.find("mul i32") != std::string::npos);
  REQUIRE(ir.find("xor i32") != std::string::npos);
  REQUIRE(ir.find("ptr %regs") == std::string::npos);
}

TEST_CASE("LLVMLifter - undeclared symbols and unsupported expressions stay unknown",
          "[llvm][lifter][expression]") {
  z3::context ctx, other;
  auto a = ctx.bv_const("a", 32), unknown = ctx.bv_const("unknown", 32);
  dragon::llvmlifter::LLVMLifter ll(dragon::Architecture::X86_64);
  REQUIRE_FALSE(ll.liftExpression(a + unknown, {a}));
  REQUIRE_FALSE(ll.liftExpression(a, {a, a}));
  REQUIRE_FALSE(ll.liftExpression(a, {a + 1}));
  REQUIRE_FALSE(ll.liftExpression(a, {other.bv_const("a", 32)}));
  // Division is supported; an undeclared divisor still stays unknown.
  REQUIRE_FALSE(ll.liftExpression(z3::udiv(a, unknown), {a}));
  auto opaque = ctx.function("opaque", ctx.bv_sort(32), ctx.bv_sort(32));
  REQUIRE_FALSE(ll.liftExpression(opaque(a), {a}));
  REQUIRE(ll.module().empty());
}

TEST_CASE("LLVMLifter - bitvector shifts keep total SMT semantics",
          "[llvm][lifter][expression]") {
  z3::context ctx;
  auto a = ctx.bv_const("a", 8), amount = ctx.bv_const("amount", 8);
  for (const auto &expression : {z3::shl(a, amount), z3::lshr(a, amount), z3::ashr(a, amount)}) {
    dragon::llvmlifter::LLVMLifter ll(dragon::Architecture::X86_64);
    REQUIRE(ll.liftExpression(expression, {a, amount}));
    REQUIRE_FALSE(llvm::verifyModule(ll.module()));
    REQUIRE(ll.ir().find("icmp ult i8 %amount, 8") != std::string::npos);
    REQUIRE(ll.ir().find("select i1") != std::string::npos);
  }
}

TEST_CASE("LLVMLifter - boolean DAGs and wide constants lower without truncation",
          "[llvm][lifter][expression]") {
  z3::context ctx;
  auto a = ctx.bv_const("a", 128);
  auto large = ctx.bv_val("1267650600228229401496703205376", 128);
  auto condition = z3::ult(a, large);
  dragon::llvmlifter::LLVMLifter ll(dragon::Architecture::X86_64);
  REQUIRE(ll.liftExpression(z3::ite(condition, a + large, a - large), {a}));
  REQUIRE(ll.liftExpression((condition || a == large) && !(a == 0), {a}, "predicate"));
  REQUIRE_FALSE(llvm::verifyModule(ll.module()));
  REQUIRE(ll.ir().find("1267650600228229401496703205376") != std::string::npos);
  REQUIRE(ll.ir().find("define i1 @predicate") != std::string::npos);
}

#include <dragon/lifters/ignil/MemoryEffects.hpp>

TEST_CASE("LLVMLifter - effect export preserves non-return stores and void returns",
          "[llvm][lifter][memory-effects]") {
  z3::context ctx;
  auto p = ctx.bv_const("p", 64), q = ctx.bv_const("q", 64);
  auto x = ctx.bv_const("x", 32);
  dragon::ignil::MemoryEffects memory(ctx);
  memory.store(p, x, 0x1000);
  auto read = memory.load(q, 32, 0x1001);
  memory.store(q, read+1, 0x1002);
  auto result = memory.load(p, 32, 0x1003);
  dragon::llvmlifter::LLVMLifter ll(dragon::Architecture::X86_64);
  REQUIRE(ll.liftEffects(&result, {p, q, x}, {true, true, false}, memory));
  REQUIRE(ll.liftEffects(nullptr, {p, q, x}, {true, true, false}, memory, "void_result"));
  REQUIRE_FALSE(llvm::verifyModule(ll.module()));
  ll.runMem2Reg(); ll.runInstCombine(); ll.runGVN(); ll.runDCE();
  REQUIRE_FALSE(llvm::verifyModule(ll.module()));
  const auto ir = ll.ir();
  REQUIRE(ir.find("define i32 @recovered(ptr %p, ptr %q, i32 %x)") != std::string::npos);
  REQUIRE(ir.find("define void @void_result(ptr %p, ptr %q, i32 %x)") != std::string::npos);
  REQUIRE(ir.find("store i32 %x, ptr %p, align 1") != std::string::npos);
  REQUIRE(ir.find("noalias") == std::string::npos);
  REQUIRE(ir.find("inbounds") == std::string::npos);
}

TEST_CASE("LLVMLifter - effect export rejects missing dependencies atomically",
          "[llvm][lifter][memory-effects]") {
  z3::context ctx;
  auto p = ctx.bv_const("p", 64), x = ctx.bv_const("x", 32);
  dragon::ignil::MemoryEffects memory(ctx);
  memory.store(p, x, 0x1000);
  dragon::llvmlifter::LLVMLifter ll(dragon::Architecture::X86_64);
  REQUIRE_FALSE(ll.liftEffects(nullptr, {p}, {true}, memory));
  REQUIRE_FALSE(ll.liftEffects(nullptr, {p, x}, {true, true}, memory));
  REQUIRE_FALSE(ll.liftEffects(nullptr, {p, x}, {}, memory));
  REQUIRE(ll.module().empty());
}
#endif
