#include "X86SemanticRoundTripFixture.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>

using namespace dragon::test;

// Compares real (Unicorn) vs lifted (JIT) final state, ignoring the flags
// X86IGNILLifter doesn't model (see maskUnmodeledFlags in the fixture).
static void
requireStatesMatch(RoundTripResult expected, RoundTripResult actual,
                   const RegBuf &initialRegs,
                   dragon::Architecture arch = dragon::Architecture::X86_64) {
  maskUnmodeledFlags(expected.regs);
  maskUnmodeledFlags(actual.regs);
  REQUIRE(expected.regs == actual.regs);
  maskSentinelSlot(expected.mem, initialRegs, arch);
  maskSentinelSlot(actual.mem, initialRegs, arch);
  if (expected.mem != actual.mem) {
    for (std::size_t i = 0; i < expected.mem.size(); ++i) {
      if (expected.mem[i] != actual.mem[i])
        FAIL("mem[" << i << "] (addr 0x" << std::hex << (kMemBase + i) << std::dec
                    << ") expected=" << (int) expected.mem[i]
                    << " actual=" << (int) actual.mem[i]);
    }
  }
}

// -----------------------------------------------------------------------
// Test 1: baseline sanity - mov/add register-only, no memory involved.
// Confirms the harness itself (Unicorn setup, JIT plumbing, comparison)
// works before trusting it to validate anything more interesting.
// -----------------------------------------------------------------------

TEST_CASE("Semantic round-trip - mov/add registers", "[semantic][x86_64]") {
  // push rbp ; mov rbp, rsp        - dragon-tales' function-start heuristic
  //   (X86Info::x8664bitIsCommonPrologue) requires this exact shape; without
  //   it the entry address is never recognized as a function and lift()
  //   has nothing to lift (see lib/disassemblers/x86/x86Analysis.cpp).
  // mov eax, 5 ; mov ebx, 3 ; add eax, ebx ; ret
  const std::vector<std::uint8_t> code = {
          0x55,                         // push rbp
          0x48, 0x89, 0xe5,             // mov rbp, rsp
          0xb8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
          0xbb, 0x03, 0x00, 0x00, 0x00, // mov ebx, 3
          0x01, 0xd8,                   // add eax, ebx
          0x5d,                         // pop rbp
          0xc3,                         // ret
  };
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem);
  auto actual = runLifted(code, initialRegs, initialMem);

  REQUIRE(getReg64(actual.regs, x86off::RAX) == 8);
  requireStatesMatch(expected, actual, initialRegs);
}

// -----------------------------------------------------------------------
// Test 2/3: the exact RMW forms fixed for ToDo/LifterGaps.md #1 -
// `add [mem], reg` and `sub [mem], imm8` - executed for real, not just
// checked for IGNIL op shape.
// -----------------------------------------------------------------------

TEST_CASE("Semantic round-trip - add [mem], reg (RMW)", "[semantic][x86_64]") {
  // push rbp ; mov rbp, rsp ; mov dword ptr [rbp-8], 10 ;
  // add dword ptr [rbp-8], eax ; ret
  const std::vector<std::uint8_t> code = {
          0x55,                                     // push rbp
          0x48, 0x89, 0xe5,                         // mov rbp, rsp
          0xc7, 0x45, 0xf8, 0x0a, 0x00, 0x00, 0x00, // mov [rbp-8], 10
          0x01, 0x45, 0xf8,                          // add [rbp-8], eax
          0x5d,                                       // pop rbp
          0xc3,                                       // ret
  };
  auto initialRegs = defaultInitialRegs();
  setReg64(initialRegs, x86off::RAX, 5);
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem);
  auto actual = runLifted(code, initialRegs, initialMem);
  requireStatesMatch(expected, actual, initialRegs);
}

TEST_CASE("Semantic round-trip - sub [mem], imm8 (RMW)", "[semantic][x86_64]") {
  // push rbp ; mov rbp, rsp ; mov dword ptr [rbp-8], 20 ;
  // sub dword ptr [rbp-8], 7 ; ret
  const std::vector<std::uint8_t> code = {
          0x55,                                     // push rbp
          0x48, 0x89, 0xe5,                         // mov rbp, rsp
          0xc7, 0x45, 0xf8, 0x14, 0x00, 0x00, 0x00, // mov [rbp-8], 20
          0x83, 0x6d, 0xf8, 0x07,                    // sub [rbp-8], 7
          0x5d,                                       // pop rbp
          0xc3,                                       // ret
  };
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem);
  auto actual = runLifted(code, initialRegs, initialMem);
  requireStatesMatch(expected, actual, initialRegs);
}

// -----------------------------------------------------------------------
// Test 4: the strongest regression test for the original bug. Before the
// fix, `cmp eax, [mem]` produced zero IGNIL ops, so CJMP would branch on
// stale flags - correct by accident at best. Running both branch
// directions for real proves the flags computed from a memory operand
// actually steer control flow correctly, not just that *some* ops appear.
// -----------------------------------------------------------------------

TEST_CASE("Semantic round-trip - cmp reg, [mem] branches correctly (not taken)",
         "[semantic][x86_64]") {
  // push rbp ; mov rbp, rsp ; mov dword ptr [rbp-20], 100 ;
  // cmp eax, [rbp-20] ; jle L2
  // mov ecx, 1 ; ret                         (fallthrough: eax > 100)
  // L2: mov ecx, 2 ; ret
  const std::vector<std::uint8_t> code = {
          0x55,                                     // push rbp
          0x48, 0x89, 0xe5,                         // mov rbp, rsp
          0xc7, 0x45, 0xec, 0x64, 0x00, 0x00, 0x00, // mov [rbp-20], 100
          0x3b, 0x45, 0xec,                          // cmp eax, [rbp-20]
          0x7e, 0x07,                                 // jle +7 -> L2
          0xb9, 0x01, 0x00, 0x00, 0x00,               // mov ecx, 1
          0x5d,                                       // pop rbp
          0xc3,                                       // ret
          0xb9, 0x02, 0x00, 0x00, 0x00,               // L2: mov ecx, 2
          0x5d,                                       // pop rbp
          0xc3,                                       // ret
  };
  auto initialRegs = defaultInitialRegs();
  setReg64(initialRegs, x86off::RAX, 200); // 200 > 100: jle not taken
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem);
  auto actual = runLifted(code, initialRegs, initialMem);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 1);
  requireStatesMatch(expected, actual, initialRegs);
}

TEST_CASE("Semantic round-trip - cmp reg, [mem] branches correctly (taken)",
         "[semantic][x86_64]") {
  const std::vector<std::uint8_t> code = {
          0x55,                                     // push rbp
          0x48, 0x89, 0xe5,                         // mov rbp, rsp
          0xc7, 0x45, 0xec, 0x64, 0x00, 0x00, 0x00, // mov [rbp-20], 100
          0x3b, 0x45, 0xec,                          // cmp eax, [rbp-20]
          0x7e, 0x07,                                 // jle +7 -> L2
          0xb9, 0x01, 0x00, 0x00, 0x00,               // mov ecx, 1
          0x5d,                                       // pop rbp
          0xc3,                                       // ret
          0xb9, 0x02, 0x00, 0x00, 0x00,               // L2: mov ecx, 2
          0x5d,                                       // pop rbp
          0xc3,                                       // ret
  };
  auto initialRegs = defaultInitialRegs();
  setReg64(initialRegs, x86off::RAX, 50); // 50 <= 100: jle taken
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem);
  auto actual = runLifted(code, initialRegs, initialMem);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 2);
  requireStatesMatch(expected, actual, initialRegs);
}

// -----------------------------------------------------------------------
// Test 5: add reg, [mem] - the second gap scripts/audit_x86_lifter_coverage.py
// found (the reg,mem direction, distinct from the RMW mem,reg form above).
// -----------------------------------------------------------------------

TEST_CASE("Semantic round-trip - add reg, [mem]", "[semantic][x86_64]") {
  // push rbp ; mov rbp, rsp ; mov dword ptr [rbp-8], 42 ;
  // add eax, [rbp-8] ; ret
  const std::vector<std::uint8_t> code = {
          0x55,                                     // push rbp
          0x48, 0x89, 0xe5,                         // mov rbp, rsp
          0xc7, 0x45, 0xf8, 0x2a, 0x00, 0x00, 0x00, // mov [rbp-8], 42
          0x03, 0x45, 0xf8,                          // add eax, [rbp-8]
          0x5d,                                       // pop rbp
          0xc3,                                       // ret
  };
  auto initialRegs = defaultInitialRegs();
  setReg64(initialRegs, x86off::RAX, 8);
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem);
  auto actual = runLifted(code, initialRegs, initialMem);

  REQUIRE(getReg64(actual.regs, x86off::RAX) == 50);
  requireStatesMatch(expected, actual, initialRegs);
}

// -----------------------------------------------------------------------
// Test: INC/DEC must not disturb CF - the whole reason they exist
// separately from ADD/SUB by 1. This is the one genuinely novel flag
// semantic in that lifter-gap batch (every other op either computes a
// flag or marks it UNDEF; this is the first "leave it completely alone"
// case), so it gets a real execution check rather than just an IGNIL-shape
// one - `requireStatesMatch` compares CF unmasked.
// -----------------------------------------------------------------------

TEST_CASE("Semantic round-trip - inc/dec leave CF exactly as a prior cmp "
          "left it",
          "[semantic][x86_64]") {
  // push rbp ; mov rbp, rsp ; mov eax, 1 ; mov ebx, 2 ; cmp eax, ebx
  //   (unsigned 1 < 2 -> CF=1) ; mov ecx, 5 ; inc ecx ; mov edx, 5 ;
  //   dec edx ; pop rbp ; ret
  const std::vector<std::uint8_t> code = {
          0x55,                         // push rbp
          0x48, 0x89, 0xe5,             // mov rbp, rsp
          0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
          0xbb, 0x02, 0x00, 0x00, 0x00, // mov ebx, 2
          0x39, 0xd8,                   // cmp eax, ebx
          0xb9, 0x05, 0x00, 0x00, 0x00, // mov ecx, 5
          0xff, 0xc1,                   // inc ecx
          0xba, 0x05, 0x00, 0x00, 0x00, // mov edx, 5
          0xff, 0xca,                   // dec edx
          0x5d,                         // pop rbp
          0xc3,                         // ret
  };
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem);
  auto actual = runLifted(code, initialRegs, initialMem);

  REQUIRE(expected.regs[x86off::CF] == 1); // sanity: the cmp really set it
  REQUIRE(actual.regs[x86off::CF] == 1); // ...and inc/dec kept it
  REQUIRE(getReg64(actual.regs, x86off::RCX) == 6);
  REQUIRE(getReg64(actual.regs, x86off::RDX) == 4);
  requireStatesMatch(expected, actual, initialRegs);
}

// -----------------------------------------------------------------------
// POPFQ / PUSHFQ - previously lifted to zero ops (silently dropped, which
// also corrupted the RSP chain). Validated for real against Unicorn.
// -----------------------------------------------------------------------

TEST_CASE("Semantic round-trip - popfq loads flags from the stack",
          "[semantic][x86_64]") {
  // push rbp ; mov rbp, rsp ; mov eax, 0xCD5 ; push rax ; popfq ; pop rbp ; ret
  //   0xCD5 sets, at their RFLAGS bit positions, CF(0) PF(2) AF(4) ZF(6)
  //   SF(7) DF(10) OF(11) - so popfq must scatter those bits into the flag
  //   registers. push rax/popfq keep the stack balanced.
  const std::vector<std::uint8_t> code = {
          0x55,                         // push rbp
          0x48, 0x89, 0xe5,             // mov rbp, rsp
          0xb8, 0xd5, 0x0c, 0x00, 0x00, // mov eax, 0xCD5
          0x50,                         // push rax
          0x9d,                         // popfq
          0x5d,                         // pop rbp
          0xc3,                         // ret
  };
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem);
  auto actual = runLifted(code, initialRegs, initialMem);

  // The modeled, non-masked flags all came from the popped 0xCD5.
  REQUIRE(actual.regs[x86off::CF] == 1);
  REQUIRE(actual.regs[x86off::ZF] == 1);
  REQUIRE(actual.regs[x86off::SF] == 1);
  REQUIRE(actual.regs[x86off::OF] == 1);
  requireStatesMatch(expected, actual, initialRegs);
}

TEST_CASE("Semantic round-trip - pushfq then popfq preserves the flags",
          "[semantic][x86_64]") {
  // push rbp ; mov rbp, rsp ; mov eax, 3 ; mov ebx, 7 ; cmp eax, ebx ;
  // pushfq ; popfq ; pop rbp ; ret
  //   cmp 3,7 borrows: CF=1, SF=1, ZF=0, OF=0. pushfq must gather those into
  //   an RFLAGS word on the stack that popfq reads back unchanged.
  const std::vector<std::uint8_t> code = {
          0x55,                         // push rbp
          0x48, 0x89, 0xe5,             // mov rbp, rsp
          0xb8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3
          0xbb, 0x07, 0x00, 0x00, 0x00, // mov ebx, 7
          0x39, 0xd8,                   // cmp eax, ebx
          0x9c,                         // pushfq
          0x9d,                         // popfq
          0x5d,                         // pop rbp
          0xc3,                         // ret
  };
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem);
  auto actual = runLifted(code, initialRegs, initialMem);

  REQUIRE(actual.regs[x86off::CF] == 1);
  REQUIRE(actual.regs[x86off::SF] == 1);
  REQUIRE(actual.regs[x86off::ZF] == 0);
  REQUIRE(actual.regs[x86off::OF] == 0);

  // Registers only: the pushfq'd word left on the stack legitimately differs
  // between the two sides (Unicorn stores the real RFLAGS incl. unmodeled
  // system bits like IF; the lifter stores only the modeled subset + the
  // reserved bit 1), so a full memory compare would flag a known, documented
  // modeling gap rather than a bug. The flags round-tripping correctly is the
  // property under test.
  maskUnmodeledFlags(expected.regs);
  maskUnmodeledFlags(actual.regs);
  REQUIRE(expected.regs == actual.regs);
}

// -----------------------------------------------------------------------
// Differential sweep: instruction forms that once lifted to nothing (or not
// at all), each run over edge-case inputs under Unicorn and through the
// lifter + JIT. IGNIL-shape tests can show ops were emitted; only this shows
// the carries, the high halves and the remainders are the right numbers.
//
// These sweeps are the expensive part of the suite: arithmeticInputs() is a
// 12x12x2 = 288-entry cross product, and a case like ADC/SBB runs it through
// every one of ~14 instruction forms, so each TEST_CASE is thousands of
// JIT-compile + emulate round-trips. On a developer laptop the whole group
// runs for the better part of a minute; on the CI box it is quick.
//
// They are therefore tagged [.][expensive]: the leading-dot tag hides them
// from a default `dragon_tests` run and from CTest discovery (so a normal
// `ctest` stays fast), while the [expensive] tag selects them explicitly:
//
//     ./build/bin/dragon_tests "[expensive]"     # run only the heavy sweeps
//     ./build/bin/dragon_tests "[semantic]"      # also pulls them in
//
// The faster, non-[vmp] semantic round-trip tests above stay in the default
// run - they are the per-gap regression checks and each takes well under a
// tenth of a second.
// -----------------------------------------------------------------------

namespace {

// Which flags an instruction defines. The rest are documented-undefined (or
// modelled more strictly than the hardware leaves them) and are not compared.
enum Flags : unsigned {
  kCF = 1, kPF = 2, kAF = 4, kZF = 8, kSF = 16, kOF = 32,
  kNone = 0,
  kAll = kCF | kPF | kAF | kZF | kSF | kOF,
  kLogic = kCF | kPF | kZF | kSF | kOF, // AF is undefined after AND/OR/XOR/TEST
};

struct Inputs {
  std::uint64_t rax, rbx, rcx, rdx;
  bool carry;
};

struct Form {
  const char *name;
  std::vector<std::uint8_t> bytes;
  unsigned flags;
  std::vector<Inputs> inputs;
};

const std::vector<Inputs> &arithmeticInputs() {
  static const std::vector<Inputs> v = [] {
    const std::uint64_t edge[] = {0,
                                  1,
                                  0x7f,
                                  0x80,
                                  0xff,
                                  0x7fffffffull,
                                  0x80000000ull,
                                  0xffffffffull,
                                  0x7fffffffffffffffull,
                                  0x8000000000000000ull,
                                  0xffffffffffffffffull,
                                  0x123456789abcdef0ull};
    std::vector<Inputs> out;
    for (std::uint64_t a: edge)
      for (std::uint64_t b: edge)
        for (bool c: {false, true})
          out.push_back({a, b, /*rcx=*/b & 63, /*rdx=*/0x5555aaaa5555aaaaull, c});
    return out;
  }();
  return v;
}

// The same edge cases, as 32-bit values.
const std::vector<Inputs> &arithmeticInputs32() {
  static const std::vector<Inputs> v = [] {
    const std::uint64_t edge[] = {0,          1,          0x7f,
                                  0x80,       0xff,       0x7fffffff,
                                  0x80000000, 0xffffffff, 0x12345678};
    std::vector<Inputs> out;
    for (std::uint64_t a: edge)
      for (std::uint64_t b: edge)
        for (bool c: {false, true})
          out.push_back({a, b, /*rcx=*/b & 31, /*rdx=*/0x5555aaaa, c});
    return out;
  }();
  return v;
}

// Dividends that cannot raise #DE for a divisor in BX/EBX: the high half
// (DX/EDX) stays well below the divisor.
const std::vector<Inputs> &divisionInputs() {
  static const std::vector<Inputs> v = {
          {100, 7, 0, 0, false},
          {0xfffffffe, 0xffffffff, 0, 0, false},
          {0x12345678, 0x1000, 0, 3, false},
          {0x0305, 0x11, 0, 0, false},
          {1, 1, 0, 0, true},
          {0x7ffe, 0x7fff, 0, 0, false},
          {0, 5, 0, 0, false},
  };
  return v;
}

void sweep(const Form &form,
           dragon::Architecture arch = dragon::Architecture::X86_64) {
  // push rbp ; mov rbp, rsp ; <instruction> ; pop rbp ; ret
  std::vector<std::uint8_t> code = {0x55, 0x48, 0x89, 0xe5};
  if (arch == dragon::Architecture::X86_32)
    code = {0x55, 0x89, 0xe5}; // no REX.W on the mov
  code.insert(code.end(), form.bytes.begin(), form.bytes.end());
  code.push_back(0x5d);
  code.push_back(0xc3);

  const std::pair<unsigned, std::uint32_t> flagRegs[] = {
          {kCF, x86off::CF}, {kPF, x86off::PF}, {kAF, x86off::AF},
          {kZF, x86off::ZF}, {kSF, x86off::SF}, {kOF, x86off::OF}};
  const std::uint32_t gprs[] = {x86off::RAX, x86off::RCX, x86off::RDX, x86off::RBX,
                                x86off::RSP, x86off::RBP, x86off::RSI, x86off::RDI};

  for (const Inputs &in: form.inputs) {
    auto regs = defaultInitialRegs();
    setReg64(regs, x86off::RAX, in.rax);
    setReg64(regs, x86off::RBX, in.rbx);
    setReg64(regs, x86off::RCX, in.rcx);
    setReg64(regs, x86off::RDX, in.rdx);
    regs[x86off::CF] = in.carry ? 1 : 0;
    std::vector<std::uint8_t> mem;

    const auto expected = runUnicorn(code, regs, mem, arch);
    const auto actual = runLifted(code, regs, mem, kCodeBase, arch);

    INFO(form.name << "  rax=0x" << std::hex << in.rax << " rbx=0x" << in.rbx
                   << " rcx=0x" << in.rcx << " rdx=0x" << in.rdx << " cf=" << in.carry);
    for (std::uint32_t reg: gprs)
      REQUIRE(getReg64(actual.regs, reg) == getReg64(expected.regs, reg));
    for (const auto &[bit, offset]: flagRegs)
      if (form.flags & bit) {
        INFO("flag at register offset " << std::dec << offset);
        REQUIRE(int(actual.regs[offset]) == int(expected.regs[offset]));
      }
  }
}

} // namespace

TEST_CASE("Semantic round-trip - ADC / SBB match the hardware, carries and all",
          "[semantic][x86_64][vmp][.][expensive]") {
  const auto &in = arithmeticInputs();
  for (const Form &form: std::vector<Form>{
               {"adc rax, rbx", {0x48, 0x11, 0xd8}, kAll, in},
               {"adc eax, ebx", {0x11, 0xd8}, kAll, in},
               {"adc ax, bx", {0x66, 0x11, 0xd8}, kAll, in},
               {"adc al, bl", {0x10, 0xd8}, kAll, in},
               {"adc rax, rax", {0x48, 0x11, 0xc0}, kAll, in},
               {"adc rax, 0x7f", {0x48, 0x83, 0xd0, 0x7f}, kAll, in},
               {"adc eax, 0x80000000 (ADC32i32)", {0x15, 0x00, 0x00, 0x00, 0x80}, kAll, in},
               {"sbb rax, rbx", {0x48, 0x19, 0xd8}, kAll, in},
               {"sbb eax, ebx", {0x19, 0xd8}, kAll, in},
               {"sbb ax, bx", {0x66, 0x19, 0xd8}, kAll, in},
               {"sbb al, bl", {0x18, 0xd8}, kAll, in},
               {"sbb rax, rax", {0x48, 0x19, 0xc0}, kAll, in},
               {"sbb rax, 1", {0x48, 0x83, 0xd8, 0x01}, kAll, in},
               {"sbb al, 5 (SBB8i8)", {0x1c, 0x05}, kAll, in},
       })
    sweep(form);
}

TEST_CASE("Semantic round-trip - one-operand MUL / IMUL produce both halves",
          "[semantic][x86_64][vmp][.][expensive]") {
  const auto &in = arithmeticInputs();
  for (const Form &form: std::vector<Form>{
               {"mul rbx", {0x48, 0xf7, 0xe3}, kCF | kOF, in},
               {"mul ebx", {0xf7, 0xe3}, kCF | kOF, in},
               {"mul bx", {0x66, 0xf7, 0xe3}, kCF | kOF, in},
               {"mul bl", {0xf6, 0xe3}, kCF | kOF, in},
               {"mul rax", {0x48, 0xf7, 0xe0}, kCF | kOF, in},
               {"mul rdx", {0x48, 0xf7, 0xe2}, kCF | kOF, in},
               {"imul rbx", {0x48, 0xf7, 0xeb}, kCF | kOF, in},
               {"imul ebx", {0xf7, 0xeb}, kCF | kOF, in},
               {"imul bx", {0x66, 0xf7, 0xeb}, kCF | kOF, in},
               {"imul bl", {0xf6, 0xeb}, kCF | kOF, in},
       })
    sweep(form);
}

TEST_CASE("Semantic round-trip - one-operand DIV / IDIV at 8, 16 and 32 bits",
          "[semantic][x86_64][vmp][.][expensive]") {
  const auto &in = divisionInputs();
  sweep({"div ebx", {0xf7, 0xf3}, kNone, in});
  sweep({"div bx", {0x66, 0xf7, 0xf3}, kNone, in});
  sweep({"idiv ebx", {0xf7, 0xfb}, kNone,
         {{100, 7, 0, 0, false},
          {0xffffff9c /* -100 */, 7, 0, 0xffffffff, false},
          {100, 0xfffffff9 /* -7 */, 0, 0, false},
          {0x12345678, 0x1000, 0, 3, false}}});
  sweep({"idiv bx", {0x66, 0xf7, 0xfb}, kNone,
         {{100, 7, 0, 0, false}, {0xff9c /* -100 */, 7, 0, 0xffff, false}}});
  // AX / BL: the quotient has to fit in AL.
  sweep({"div bl", {0xf6, 0xf3}, kNone,
         {{100, 7, 0, 0, false}, {0x0305, 0x11, 0, 0, false}, {0, 5, 0, 0, false}}});
  sweep({"idiv bl", {0xf6, 0xfb}, kNone,
         {{100, 7, 0, 0, false}, {0xff9c /* -100 */, 7, 0, 0, false}}});
}

TEST_CASE("Semantic round-trip - accumulator short forms and BT",
          "[semantic][x86_64][vmp][.][expensive]") {
  const auto &in = arithmeticInputs();
  for (const Form &form: std::vector<Form>{
               {"sub al, 0x22 (SUB8i8)", {0x2c, 0x22}, kAll, in},
               {"sub ax, 0xe9ab (SUB16i16)", {0x66, 0x2d, 0xab, 0xe9}, kAll, in},
               {"add rax, 0x7fffffff (ADD64i32)", {0x48, 0x05, 0xff, 0xff, 0xff, 0x7f}, kAll, in},
               {"cmp eax, 0x80000000 (CMP32i32)", {0x3d, 0x00, 0x00, 0x00, 0x80}, kAll, in},
               {"or al, 2 (OR8i8)", {0x0c, 0x02}, kLogic, in},
               {"xor eax, 0x11223344 (XOR32i32)", {0x35, 0x44, 0x33, 0x22, 0x11}, kLogic, in},
               {"and rax, -16 (AND64i32)", {0x48, 0x25, 0xf0, 0xff, 0xff, 0xff}, kLogic, in},
               {"test al, 5 (TEST8i8)", {0xa8, 0x05}, kLogic, in},
               {"bt rax, 63", {0x48, 0x0f, 0xba, 0xe0, 0x3f}, kCF, in},
               {"bt eax, ecx", {0x0f, 0xa3, 0xc8}, kCF, in},
               {"bt ax, cx", {0x66, 0x0f, 0xa3, 0xc8}, kCF, in},
       })
    sweep(form);
}

TEST_CASE("Semantic round-trip - SETcc agrees with the hardware for all sixteen "
          "conditions",
          "[semantic][x86_64][vmp][.][expensive]") {
  // cmp al, bl ; setcc cl   - an 8-bit compare reaches every flag, PF and OF
  // included, with small operands. The condition is the low nibble of the
  // second opcode byte: 0F 90+cc /r.
  const char *names[16] = {"seto", "setno", "setb",  "setae", "sete", "setne",
                           "setbe", "seta", "sets",  "setns", "setp", "setnp",
                           "setl",  "setge", "setle", "setg"};
  std::vector<Inputs> inputs;
  for (std::uint64_t a: {0x00ull, 0x01ull, 0x03ull, 0x7full, 0x80ull, 0x81ull, 0xffull})
    for (std::uint64_t b: {0x00ull, 0x01ull, 0x02ull, 0x7full, 0x80ull, 0xffull})
      inputs.push_back({a, b, /*rcx=*/0xdeadbeefcafef00dull, 0, false});

  for (std::uint8_t cc = 0; cc < 16; ++cc)
    sweep({names[cc],
           {0x38, 0xd8,                                       // cmp al, bl
            0x0f, static_cast<std::uint8_t>(0x90 + cc), 0xc1}, // setcc cl
           kAll,
           inputs});
}

// feat/x86-lift-rotates-bitops: the variable-count shifts and rotates now emit
// a CONCRETE overflow flag (so VMProtect's pushfq-folded RFLAGS stays
// resolvable) instead of UNDEF. With CL == 1 the OF is architecturally
// DEFINED, so this sweep compares it against the hardware; it is the check
// that the modelled OF is right, not merely concrete. A handful of larger CL
// counts (OF undefined, not compared) confirm the result and the other flags
// were not disturbed.
TEST_CASE("Semantic round-trip - shifts/rotates by CL: OF modelled, not UNDEF",
          "[semantic][x86_64][vmp][.][expensive]") {
  std::vector<Inputs> cl1; // count exactly 1: OF is defined
  for (std::uint64_t a: {0ull, 1ull, 2ull, 0x7full, 0x80ull, 0xffull,
                         0x7fffffffull, 0x80000000ull, 0xffffffffull,
                         0x4000000000000000ull, 0x8000000000000000ull,
                         0xffffffffffffffffull, 0x123456789abcdef0ull})
    cl1.push_back({a, 0, /*rcx=*/1, 0, false});

  const unsigned shf = kCF | kPF | kZF | kSF | kOF; // AF undefined for shifts
  const unsigned rot = kCF | kOF;                   // rotates touch only CF/OF
  const Form defined[] = {
          {"shl eax,cl (1)", {0xd3, 0xe0}, shf, cl1},
          {"shr eax,cl (1)", {0xd3, 0xe8}, shf, cl1},
          {"sar eax,cl (1)", {0xd3, 0xf8}, shf, cl1},
          {"shl rax,cl (1)", {0x48, 0xd3, 0xe0}, shf, cl1},
          {"shr rax,cl (1)", {0x48, 0xd3, 0xe8}, shf, cl1},
          {"sar rax,cl (1)", {0x48, 0xd3, 0xf8}, shf, cl1},
          {"rol eax,cl (1)", {0xd3, 0xc0}, rot, cl1},
          {"ror eax,cl (1)", {0xd3, 0xc8}, rot, cl1},
          {"rcl eax,cl (1)", {0xd3, 0xd0}, rot, cl1},
          {"rcr eax,cl (1)", {0xd3, 0xd8}, rot, cl1},
          {"rol rax,cl (1)", {0x48, 0xd3, 0xc0}, rot, cl1},
          {"ror rax,cl (1)", {0x48, 0xd3, 0xc8}, rot, cl1},
  };
  for (const Form &f: defined)
    sweep(f);

  // Larger counts: OF is architecturally undefined (not compared), but CF, the
  // sign/zero/parity flags and the result must still match the hardware.
  std::vector<Inputs> cln;
  for (std::uint64_t a: {1ull, 0xffull, 0x8000000000000000ull, 0x123456789abcdef0ull})
    for (std::uint64_t n: {0ull, 3ull, 7ull, 31ull})
      cln.push_back({a, 0, /*rcx=*/n, 0, false});
  const Form undefinedOF[] = {
          {"shl eax,cl (n)", {0xd3, 0xe0}, kCF | kPF | kZF | kSF, cln},
          {"shr eax,cl (n)", {0xd3, 0xe8}, kCF | kPF | kZF | kSF, cln},
          {"sar eax,cl (n)", {0xd3, 0xf8}, kCF | kPF | kZF | kSF, cln},
          {"rol eax,cl (n)", {0xd3, 0xc0}, kCF, cln},
          {"ror eax,cl (n)", {0xd3, 0xc8}, kCF, cln},
  };
  for (const Form &f: undefinedOF)
    sweep(f);
}

// i386 sweeps of forms first written for x64.
TEST_CASE("Semantic round-trip - i386 32-bit ALU and moves",
          "[semantic][x86_32][.][expensive]") {
  const auto &in = arithmeticInputs32();
  for (const Form &form: std::vector<Form>{
               {"add eax, ebx", {0x01, 0xd8}, kAll, in},
               {"add ebx, 0x12345678 (ADD32ri)",
                {0x81, 0xc3, 0x78, 0x56, 0x34, 0x12},
                kAll,
                in},
               {"sub eax, ebx", {0x29, 0xd8}, kAll, in},
               {"sub ebx, 0x80000000 (SUB32ri)",
                {0x81, 0xeb, 0x00, 0x00, 0x00, 0x80},
                kAll,
                in},
               {"adc eax, ebx", {0x11, 0xd8}, kAll, in},
               {"neg eax", {0xf7, 0xd8}, kAll, in},
               {"xor eax, ebx", {0x31, 0xd8}, kLogic, in},
               {"xor ebx, 0x38 (XOR32ri)",
                {0x81, 0xf3, 0x38, 0x00, 0x00, 0x00},
                kLogic,
                in},
               {"and ebx, 0xff (AND32ri)",
                {0x81, 0xe3, 0xff, 0x00, 0x00, 0x00},
                kLogic,
                in},
               {"mov eax, ebx", {0x89, 0xd8}, kNone, in},
               {"mov eax, 0xfffffffc",
                {0xb8, 0xfc, 0xff, 0xff, 0xff},
                kNone,
                in},
               {"lea eax, [ebx+4*edx]", {0x8d, 0x04, 0x93}, kNone, in},
               {"movzx edx, al", {0x0f, 0xb6, 0xd0}, kNone, in},
       })
    sweep(form, dragon::Architecture::X86_32);
}

TEST_CASE("Semantic round-trip - i386 shifts and rotates",
          "[semantic][x86_32][.][expensive]") {
  // CL = b & 31: counts 0, 1, 24 and 31. OF only for the by-1 forms.
  const auto &in = arithmeticInputs32();
  const unsigned shf = kCF | kPF | kZF | kSF;
  for (const Form &form: std::vector<Form>{
               {"shl eax, 16", {0xc1, 0xe0, 0x10}, shf, in},
               {"shr ebx, 3", {0xc1, 0xeb, 0x03}, shf, in},
               {"shl bl, 3", {0xc0, 0xe3, 0x03}, shf, in},
               {"shr al, 3", {0xc0, 0xe8, 0x03}, shf, in},
               {"shl ebx", {0xd1, 0xe3}, shf | kOF, in},
               {"shr eax", {0xd1, 0xe8}, shf | kOF, in},
               {"shl bl", {0xd0, 0xe3}, shf | kOF, in},
               {"shr al", {0xd0, 0xe8}, shf | kOF, in},
               {"shl eax, cl", {0xd3, 0xe0}, shf, in},
               {"shr ebx, cl", {0xd3, 0xeb}, shf, in},
               {"rol eax, 16", {0xc1, 0xc0, 0x10}, kCF, in},
               {"ror ebx, 5", {0xc1, 0xcb, 0x05}, kCF, in},
               {"ror eax, cl", {0xd3, 0xc8}, kCF, in},
               {"ror al, cl", {0xd2, 0xc8}, kCF, in},
               {"rol bl, cl", {0xd2, 0xc3}, kCF, in},
       })
    sweep(form, dragon::Architecture::X86_32);
}

TEST_CASE("Semantic round-trip - i386 8-bit ALU and moves",
          "[semantic][x86_32][.][expensive]") {
  const auto &in = arithmeticInputs32();
  for (const Form &form: std::vector<Form>{
               {"add al, bl", {0x00, 0xd8}, kAll, in},
               {"sub al, bl", {0x28, 0xd8}, kAll, in},
               {"sub bl, 1", {0x80, 0xeb, 0x01}, kAll, in},
               {"xor bl, 0xf2", {0x80, 0xf3, 0xf2}, kLogic, in},
               {"mov al, bl", {0x88, 0xd8}, kNone, in},
               {"mov al, 0xea", {0xb0, 0xea}, kNone, in},
       })
    sweep(form, dragon::Architecture::X86_32);
}

TEST_CASE("Semantic round-trip - i386 accumulator short forms",
          "[semantic][x86_32][.][expensive]") {
  const auto &in = arithmeticInputs32();
  for (const Form &form: std::vector<Form>{
               {"xor al, 0x44 (XOR8i8)", {0x34, 0x44}, kLogic, in},
               {"sub al, 0xed (SUB8i8)", {0x2c, 0xed}, kAll, in},
               {"and eax, 0xffffffdf (AND32i32)",
                {0x25, 0xdf, 0xff, 0xff, 0xff},
                kLogic,
                in},
               {"xor eax, 0x26 (XOR32i32)",
                {0x35, 0x26, 0x00, 0x00, 0x00},
                kLogic,
                in},
               {"sub eax, 0xbe (SUB32i32)",
                {0x2d, 0xbe, 0x00, 0x00, 0x00},
                kAll,
                in},
               {"add eax, 4 (ADD32i32)",
                {0x05, 0x04, 0x00, 0x00, 0x00},
                kAll,
                in},
       })
    sweep(form, dragon::Architecture::X86_32);
}

TEST_CASE("Semantic round-trip - i386 push/pop and xchg registers",
          "[semantic][x86_32][.][expensive]") {
  // Each push is paired with a pop.
  const auto &in = arithmeticInputs32();
  for (const Form &form: std::vector<Form>{
               {"push eax ; pop ecx", {0x50, 0x59}, kNone, in},
               {"push ebx ; pop eax", {0x53, 0x58}, kNone, in},
               {"push 0x9095 ; pop edx",
                {0x68, 0x95, 0x90, 0x00, 0x00, 0x5a},
                kNone,
                in},
               {"xchg ebx, edx", {0x87, 0xda}, kNone, in},
               {"xchg eax, ebx (XCHG32ar)", {0x93}, kNone, in},
               {"xchg al, bl", {0x86, 0xd8}, kNone, in},
       })
    sweep(form, dragon::Architecture::X86_32);
}

TEST_CASE("Semantic round-trip - i386 memory operands",
          "[semantic][x86_32][.][expensive]") {
  // push ebx ; <op on [esp]> ; pop ecx: the result lands in ECX.
  const auto &in = arithmeticInputs32();
  const auto onStack = [](std::vector<std::uint8_t> op) {
    op.insert(op.begin(), 0x53); // push ebx
    op.push_back(0x59); // pop ecx
    return op;
  };
  for (const Form &form: std::vector<Form>{
               {"mov eax, [esp]", onStack({0x8b, 0x04, 0x24}), kNone, in},
               {"mov [esp], eax", onStack({0x89, 0x04, 0x24}), kNone, in},
               {"mov dword [esp], 0x2140ae2e",
                onStack({0xc7, 0x04, 0x24, 0x2e, 0xae, 0x40, 0x21}), kNone, in},
               {"mov al, [esp+1]", onStack({0x8a, 0x44, 0x24, 0x01}), kNone,
                in},
               {"movzx eax, word [esp]", onStack({0x0f, 0xb7, 0x04, 0x24}),
                kNone, in},
               {"add eax, [esp]", onStack({0x03, 0x04, 0x24}), kAll, in},
               {"add [esp], eax", onStack({0x01, 0x04, 0x24}), kAll, in},
               {"add dword [esp], 4 (ADD32mi)",
                onStack({0x81, 0x04, 0x24, 0x04, 0x00, 0x00, 0x00}), kAll, in},
               {"sub [esp], eax", onStack({0x29, 0x04, 0x24}), kAll, in},
               {"sub dword [esp], 27 (SUB32mi)",
                onStack({0x81, 0x2c, 0x24, 0x1b, 0x00, 0x00, 0x00}), kAll, in},
               {"inc dword [esp]", onStack({0xff, 0x04, 0x24}), kAll, in},
               {"dec byte [esp]", onStack({0xfe, 0x0c, 0x24}), kAll, in},
               {"lock dec byte [esp]", onStack({0xf0, 0xfe, 0x0c, 0x24}), kAll,
                in},
               {"cmp dword [esp], 0x2140ae2e",
                onStack({0x81, 0x3c, 0x24, 0x2e, 0xae, 0x40, 0x21}), kAll, in},
               {"cmp [esp], eax", onStack({0x39, 0x04, 0x24}), kAll, in},
       })
    sweep(form, dragon::Architecture::X86_32);
}

TEST_CASE("Semantic round-trip - i386 branches",
          "[semantic][x86_32][.][expensive]") {
  // Each branch jumps over `mov ecx, 1`. `jmp reg` is not swept: LLVMLifter
  // lowers an indirect JMP to unreachable.
  const auto &in = arithmeticInputs32();
  const auto overMovEcx = [](std::vector<std::uint8_t> branch) {
    branch.insert(branch.end(), {0xb9, 0x01, 0x00, 0x00, 0x00});
    return branch;
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  sweep({"jmp short", overMovEcx({0xeb, 0x05}), kNone, in}, arch);
  sweep({"jmp near", overMovEcx({0xe9, 0x05, 0x00, 0x00, 0x00}), kNone, in},
        arch);
  sweep({"test eax, eax ; jns short", overMovEcx({0x85, 0xc0, 0x79, 0x05}),
         kLogic, in},
        arch);

  // cmp eax, ebx ; jcc rel32, for all sixteen conditions.
  const char *names[16] = {"jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja",
                           "js", "jns", "jp", "jnp", "jl", "jge", "jle", "jg"};
  for (std::uint8_t cc = 0; cc < 16; ++cc)
    sweep({names[cc],
           overMovEcx({0x39, 0xd8, 0x0f, static_cast<std::uint8_t>(0x80 + cc),
                       0x05, 0x00, 0x00, 0x00}),
           kAll, in},
          arch);
}

// -----------------------------------------------------------------------
// i386 baseline: instructions that already lift, to check the harness.
// -----------------------------------------------------------------------

TEST_CASE("Semantic round-trip - i386 mov/add/push/pop registers",
          "[semantic][x86_32]") {
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0xb8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5
          0xbb, 0x03, 0x00, 0x00, 0x00, // mov ebx, 3
          0x01, 0xd8, // add eax, ebx
          0x50, // push eax
          0x59, // pop ecx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 8);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 pushfd stores the flags word",
          "[semantic][x86_32]") {
  // cmp 3, 7 sets CF, PF, AF and SF: 0x97 with the reserved bit 1.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0xb8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3
          0xbb, 0x07, 0x00, 0x00, 0x00, // mov ebx, 7
          0x39, 0xd8, // cmp eax, ebx
          0x9c, // pushfd
          0x59, // pop ecx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0x97);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 popfd loads flags from the stack",
          "[semantic][x86_32]") {
  // 0xCD5 sets CF, PF, AF, ZF, SF, DF and OF.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0xb8, 0xd5, 0x0c, 0x00, 0x00, // mov eax, 0xCD5
          0x50, // push eax
          0x9d, // popfd
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(actual.regs[x86off::CF] == 1);
  REQUIRE(actual.regs[x86off::ZF] == 1);
  REQUIRE(actual.regs[x86off::SF] == 1);
  REQUIRE(actual.regs[x86off::OF] == 1);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 pushad stores all eight registers",
          "[semantic][x86_32]") {
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x60, // pushad
          0x83, 0xc4, 0x20, // add esp, 32
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  setReg64(initialRegs, x86off::RAX, 0x11111111);
  setReg64(initialRegs, x86off::RCX, 0x22222222);
  setReg64(initialRegs, x86off::RDX, 0x33333333);
  setReg64(initialRegs, x86off::RBX, 0x44444444);
  setReg64(initialRegs, x86off::RSI, 0x77777777);
  setReg64(initialRegs, x86off::RDI, 0x88888888);
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 popad loads all but ESP",
          "[semantic][x86_32]") {
  // popad's EBP is stored before pop ebp overwrites it.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x68, 0x11, 0x11, 0x11, 0x11, // push 0x11111111 (eax)
          0x68, 0x22, 0x22, 0x22, 0x22, // push 0x22222222 (ecx)
          0x68, 0x33, 0x33, 0x33, 0x33, // push 0x33333333 (edx)
          0x68, 0x44, 0x44, 0x44, 0x44, // push 0x44444444 (ebx)
          0x68, 0xef, 0xbe, 0xad, 0xde, // push 0xDEADBEEF (esp, skipped)
          0x68, 0x66, 0x66, 0x66, 0x66, // push 0x66666666 (ebp)
          0x68, 0x77, 0x77, 0x77, 0x77, // push 0x77777777 (esi)
          0x68, 0x88, 0x88, 0x88, 0x88, // push 0x88888888 (edi)
          0x61, // popad
          0x89, 0x6c, 0x24, 0xfc, // mov [esp-4], ebp
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RAX) == 0x11111111);
  REQUIRE(getReg64(actual.regs, x86off::RDI) == 0x88888888);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 push ss moves ESP by 4",
          "[semantic][x86_32]") {
  // The UNDEF selector is overwritten before it is read.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x16, // push ss
          0xc7, 0x04, 0x24, 0x78, 0x56, 0x34, 0x12, // mov [esp], 0x12345678
          0x59, // pop ecx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0x12345678);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 dec reg short form overflows",
          "[semantic][x86_32]") {
  // INT_MIN - 1 sets OF.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0xba, 0x00, 0x00, 0x00, 0x80, // mov edx, 0x80000000
          0x4a, // dec edx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RDX) == 0x7fffffff);
  REQUIRE(actual.regs[x86off::OF] == 1);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - a sub-register read sees the parent's write",
          "[semantic][x86_64]") {
  // Each width has its own slot in LLVMLifter: writing ECX has to refresh
  // CX and CL, and writing RDX has to refresh EDX.
  const std::vector<std::uint8_t> code = {
          0x55, // push rbp
          0x48, 0x89, 0xe5, // mov rbp, rsp
          0x66, 0x41, 0x89, 0xc8, // mov r8w, cx (reads CX before the write)
          0xb9, 0x34, 0x12, 0x00, 0x00, // mov ecx, 0x1234
          0x88, 0xc8, // mov al, cl
          0x66, 0x89, 0xcb, // mov bx, cx
          0x48, 0xba, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
          0x11, // mov rdx, 0x1122334455667788
          0x89, 0xd6, // mov esi, edx
          0x5d, // pop rbp
          0xc3, // ret
  };
  auto initialRegs = defaultInitialRegs();
  setReg64(initialRegs, x86off::RCX, 0xaaaaaaaabbbbccccULL);
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem);
  auto actual = runLifted(code, initialRegs, initialMem);

  REQUIRE((getReg64(actual.regs, x86off::RAX) & 0xff) == 0x34);
  REQUIRE((getReg64(actual.regs, x86off::RBX) & 0xffff) == 0x1234);
  REQUIRE((getReg64(actual.regs, x86off::R8) & 0xffff) == 0xcccc);
  REQUIRE(getReg64(actual.regs, x86off::RSI) == 0x55667788);
  requireStatesMatch(expected, actual, initialRegs);
}

TEST_CASE("Semantic round-trip - i386 inc/dec short forms",
          "[semantic][x86_32]") {
  // INC/DEC leave CF alone: stc first so a stray CF write shows up.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0xb8, 0xff, 0xff, 0xff, 0x7f, // mov eax, 0x7FFFFFFF
          0xb9, 0xff, 0xff, 0x00, 0x00, // mov ecx, 0xFFFF
          0x31, 0xd2, // xor edx, edx
          0xf9, // stc
          0x40, // inc eax (INC32r_alt): OF set
          0x66, 0x41, // inc cx (INC16r_alt): wraps to 0
          0x66, 0x4a, // dec dx (DEC16r_alt): 0xFFFF, SF set
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RAX) == 0x80000000);
  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0);
  REQUIRE(getReg64(actual.regs, x86off::RDX) == 0xffff);
  REQUIRE(actual.regs[x86off::CF] == 1);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 cld clears DF", "[semantic][x86_32]") {
  // popfd sets DF only.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x68, 0x00, 0x04, 0x00, 0x00, // push 0x400
          0x9d, // popfd
          0xfc, // cld
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(actual.regs[x86off::DF] == 0);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 add byte [mem], reg",
          "[semantic][x86_32]") {
  // A 32-bit add would give 0x11223434 with CF clear.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x68, 0x44, 0x33, 0x22, 0x11, // push 0x11223344
          0xb0, 0xf0, // mov al, 0xF0
          0x00, 0x04, 0x24, // add byte [esp], al
          0x59, // pop ecx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0x11223334);
  REQUIRE(actual.regs[x86off::CF] == 1);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 mov byte [mem], imm",
          "[semantic][x86_32]") {
  // LLVM sign-extends the 0xF0 immediate to -16.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x68, 0x44, 0x33, 0x22, 0x11, // push 0x11223344
          0xc6, 0x04, 0x24, 0xf0, // mov byte [esp], 0xF0
          0x59, // pop ecx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0x112233f0);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 cmp byte [mem], imm",
          "[semantic][x86_32]") {
  // A 32-bit compare would leave ZF clear.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x68, 0x00, 0x33, 0x22, 0x11, // push 0x11223300
          0x80, 0x3c, 0x24, 0x00, // cmp byte [esp], 0
          0x59, // pop ecx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(actual.regs[x86off::ZF] == 1);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 xor reg, [mem]", "[semantic][x86_32]") {
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x68, 0x0f, 0x0f, 0x0f, 0x0f, // push 0x0F0F0F0F
          0xb8, 0x00, 0x00, 0xff, 0xff, // mov eax, 0xFFFF0000
          0x33, 0x04, 0x24, // xor eax, [esp]
          0x59, // pop ecx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RAX) == 0xf0f00f0f);
  REQUIRE(actual.regs[x86off::SF] == 1);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 xor [mem], imm", "[semantic][x86_32]") {
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x68, 0x44, 0x33, 0x22, 0x11, // push 0x11223344
          0x81, 0x34, 0x24, 0x01, 0x00, 0x00, 0x80, // xor [esp], 0x80000001
          0x59, // pop ecx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0x91223345);
  REQUIRE(actual.regs[x86off::SF] == 1);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 xor [mem], reg", "[semantic][x86_32]") {
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x68, 0x44, 0x33, 0x22, 0x11, // push 0x11223344
          0xb8, 0x44, 0x33, 0x22, 0x11, // mov eax, 0x11223344
          0x31, 0x04, 0x24, // xor [esp], eax
          0x59, // pop ecx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0);
  REQUIRE(actual.regs[x86off::ZF] == 1);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 and [mem], reg", "[semantic][x86_32]") {
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x68, 0xf0, 0xf0, 0xf0, 0xf0, // push 0xF0F0F0F0
          0xb8, 0xff, 0xff, 0x00, 0x80, // mov eax, 0x8000FFFF
          0x21, 0x04, 0x24, // and [esp], eax
          0x59, // pop ecx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0x8000f0f0);
  REQUIRE(actual.regs[x86off::SF] == 1);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 push [esp+4] reads the old stack",
          "[semantic][x86_32]") {
  // With the moved ESP, [esp+4] would be 0x22222222.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x68, 0x11, 0x11, 0x11, 0x11, // push 0x11111111
          0x68, 0x22, 0x22, 0x22, 0x22, // push 0x22222222
          0xff, 0x74, 0x24, 0x04, // push dword [esp+4]
          0x59, // pop ecx
          0x83, 0xc4, 0x08, // add esp, 8
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0x11111111);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 pop [esp+4] uses the new ESP",
          "[semantic][x86_32]") {
  // The old ESP would give ECX = C and EDX = A.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x68, 0xaa, 0xaa, 0xaa, 0xaa, // push 0xAAAAAAAA
          0x68, 0xbb, 0xbb, 0xbb, 0xbb, // push 0xBBBBBBBB
          0x68, 0xcc, 0xcc, 0xcc, 0xcc, // push 0xCCCCCCCC
          0x8f, 0x44, 0x24, 0x04, // pop dword [esp+4]
          0x59, // pop ecx
          0x5a, // pop edx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0xbbbbbbbb);
  REQUIRE(getReg64(actual.regs, x86off::RDX) == 0xcccccccc);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 xchg [mem], esp switches stacks",
          "[semantic][x86_32]") {
  // Switches to the stack whose top is at [esi], then back.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x83, 0xec, 0x20, // sub esp, 0x20
          0x8d, 0x75, 0xf0, // lea esi, [ebp-0x10]
          0x8d, 0x45, 0xc0, // lea eax, [ebp-0x40]
          0x89, 0x06, // mov [esi], eax
          0x87, 0x26, // xchg [esi], esp
          0x68, 0x78, 0x56, 0x34, 0x12, // push 0x12345678
          0x59, // pop ecx
          0x87, 0x26, // xchg [esi], esp
          0x89, 0xec, // mov esp, ebp
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0x12345678);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 xchg byte [mem], reg",
          "[semantic][x86_32]") {
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x68, 0x44, 0x33, 0x22, 0x11, // push 0x11223344
          0xb0, 0xaa, // mov al, 0xAA
          0x86, 0x04, 0x24, // xchg byte [esp], al
          0x59, // pop ecx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RAX) == 0x44);
  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0x112233aa);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 ror [mem], cl", "[semantic][x86_32]") {
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x68, 0x78, 0x56, 0x34, 0x12, // push 0x12345678
          0xb1, 0x04, // mov cl, 4
          0xd3, 0x0c, 0x24, // ror dword [esp], cl
          0x59, // pop ecx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0x81234567);
  REQUIRE(actual.regs[x86off::CF] == 1);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 ror al, cl by a multiple of 8 sets CF",
          "[semantic][x86_32]") {
  // AL is unchanged, but the count is not 0, so CF is written.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0xb0, 0x81, // mov al, 0x81
          0xb1, 0x08, // mov cl, 8
          0xd2, 0xc8, // ror al, cl
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RAX) == 0x81);
  REQUIRE(actual.regs[x86off::CF] == 1);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 shr [mem], cl", "[semantic][x86_32]") {
  // A 1-bit shift, so OF is defined.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x68, 0x01, 0x00, 0x00, 0x80, // push 0x80000001
          0xb1, 0x01, // mov cl, 1
          0xd3, 0x2c, 0x24, // shr dword [esp], cl
          0x59, // pop ecx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0x40000000);
  REQUIRE(actual.regs[x86off::CF] == 1);
  REQUIRE(actual.regs[x86off::OF] == 1);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 btr [mem], imm", "[semantic][x86_32]") {
  // The index wraps at the operand width: 38 is bit 6.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0x68, 0xff, 0x00, 0x00, 0x00, // push 0xFF
          0x0f, 0xba, 0x34, 0x24, 0x26, // btr dword [esp], 38
          0x59, // pop ecx
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0xbf);
  REQUIRE(actual.regs[x86off::CF] == 1);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 loop counts ECX down",
          "[semantic][x86_32]") {
  // loop leaves the last add's flags alone.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0xb9, 0x05, 0x00, 0x00, 0x00, // mov ecx, 5
          0x31, 0xc0, // xor eax, eax
          0x83, 0xc0, 0x02, // L: add eax, 2
          0xe2, 0xfb, // loop L
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RAX) == 10);
  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0);
  requireStatesMatch(expected, actual, initialRegs, arch);
}

TEST_CASE("Semantic round-trip - i386 loop with 0x67 counts CX down",
          "[semantic][x86_32]") {
  // Only CX takes part: 3 iterations, and ECX's upper half survives.
  const std::vector<std::uint8_t> code = {
          0x55, // push ebp
          0x89, 0xe5, // mov ebp, esp
          0xb9, 0x03, 0x00, 0x01, 0x00, // mov ecx, 0x10003
          0x31, 0xc0, // xor eax, eax
          0x83, 0xc0, 0x02, // L: add eax, 2
          0x67, 0xe2, 0xfa, // loopw L
          0x5d, // pop ebp
          0xc3, // ret
  };
  constexpr auto arch = dragon::Architecture::X86_32;
  auto initialRegs = defaultInitialRegs();
  std::vector<std::uint8_t> initialMem;

  auto expected = runUnicorn(code, initialRegs, initialMem, arch);
  auto actual = runLifted(code, initialRegs, initialMem, kCodeBase, arch);

  REQUIRE(getReg64(actual.regs, x86off::RAX) == 6);
  REQUIRE(getReg64(actual.regs, x86off::RCX) == 0x10000);
  requireStatesMatch(expected, actual, initialRegs, arch);
}


TEST_CASE("Semantic round-trip - x64 pop [rsp+8] uses post-increment RSP",
          "[semantic][x86_64]") {
  const std::vector<std::uint8_t> code = {
      0x50,                         // push rax
      0x8f, 0x44, 0x24, 0x08,       // pop qword ptr [rsp+8]
      0xc3,
  };
  auto regs = defaultInitialRegs();
  setReg64(regs, x86off::RAX, 0x123456789abcdef0ULL);
  std::vector<std::uint8_t> mem;
  requireStatesMatch(runUnicorn(code, regs, mem), runLifted(code, regs, mem), regs);
}

TEST_CASE("Semantic round-trip - x64 pop [rbp+riz] handles no-index SIB",
          "[semantic][x86_64]") {
  const std::vector<std::uint8_t> code = {
      0x55,                         // push rbp
      0x48, 0x89, 0xe5,             // mov rbp, rsp
      0x50,                         // push rax
      0x8f, 0x44, 0x25, 0x10,       // pop qword ptr [rbp+riz+16]
      0x5d,                         // pop rbp
      0xc3,
  };
  auto regs = defaultInitialRegs();
  setReg64(regs, x86off::RAX, 0xfedcba9876543210ULL);
  std::vector<std::uint8_t> mem;
  requireStatesMatch(runUnicorn(code, regs, mem), runLifted(code, regs, mem), regs);
}


TEST_CASE("Semantic round-trip - x64 FS/GS memory bases are independent",
          "[semantic][x86_64][segment]") {
  // mov rax,gs:[0x60]; mov fs:[rcx+rdx*4+0x10],rax; ret
  const std::vector<std::uint8_t> code = {
      0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0, 0, 0,
      0x64, 0x48, 0x89, 0x44, 0x91, 0x10, 0xc3,
  };
  auto regs = defaultInitialRegs();
  setReg64(regs, x86off::GSBASE, kMemBase);
  setReg64(regs, x86off::FSBASE, kMemBase + 0x100);
  setReg64(regs, x86off::RCX, 0x20);
  setReg64(regs, x86off::RDX, 3);
  std::vector<std::uint8_t> mem(kMemSize, 0);
  const std::uint64_t value = 0x123456789abcdef0ULL;
  std::memcpy(mem.data() + 0x60, &value, sizeof(value));
  auto actual = runLifted(code, regs, mem);
  REQUIRE(getReg64(actual.regs, x86off::RAX) == value);
  std::uint64_t stored = 0;
  std::memcpy(&stored, actual.mem.data() + 0x13c, sizeof(stored));
  REQUIRE(stored == value);
  requireStatesMatch(runUnicorn(code, regs, mem), actual, regs);
}

TEST_CASE("Semantic round-trip - x64 LEA ignores FS/GS overrides",
          "[semantic][x86_64][segment]") {
  // lea rax,gs:[rcx+rdx*4+0x10]; lea rbx,fs:[rcx-8]; ret
  const std::vector<std::uint8_t> code = {
      0x65, 0x48, 0x8d, 0x44, 0x91, 0x10,
      0x64, 0x48, 0x8d, 0x59, 0xf8, 0xc3,
  };
  auto regs = defaultInitialRegs();
  setReg64(regs, x86off::GSBASE, 0x7ffd0000);
  setReg64(regs, x86off::FSBASE, 0x7ffe0000);
  setReg64(regs, x86off::RCX, 0x20);
  setReg64(regs, x86off::RDX, 3);
  auto actual = runLifted(code, regs, {});
  REQUIRE(getReg64(actual.regs, x86off::RAX) == 0x3c);
  REQUIRE(getReg64(actual.regs, x86off::RBX) == 0x18);
  requireStatesMatch(runUnicorn(code, regs, {}), actual, regs);
}

TEST_CASE("Semantic round-trip - x64 addr32 wraps before FS base addition",
          "[semantic][x86_64][segment]") {
  // mov rax,fs:[ecx+0x30]; ret -- offset wraps to 0x10, not 0x100000010.
  const std::vector<std::uint8_t> code = {
      0x64, 0x67, 0x48, 0x8b, 0x41, 0x30, 0xc3,
  };
  auto regs = defaultInitialRegs();
  setReg64(regs, x86off::FSBASE, kMemBase);
  setReg64(regs, x86off::RCX, 0x12345678ffffffe0ULL);
  std::vector<std::uint8_t> mem(kMemSize, 0);
  const std::uint64_t value = 0xaabbccdd11223344ULL;
  std::memcpy(mem.data() + 0x10, &value, sizeof(value));
  auto actual = runLifted(code, regs, mem);
  REQUIRE(getReg64(actual.regs, x86off::RAX) == value);
  requireStatesMatch(runUnicorn(code, regs, mem), actual, regs);
}

TEST_CASE("Semantic round-trip - x64 GS combines with RIP relative addressing",
          "[semantic][x86_64][segment]") {
  // mov rax,gs:[rip+0x17]; ret -- effective offset 0x101f.
  const std::vector<std::uint8_t> code = {
      0x65, 0x48, 0x8b, 0x05, 0x17, 0, 0, 0, 0xc3,
  };
  auto regs = defaultInitialRegs();
  setReg64(regs, x86off::GSBASE, kMemBase - kCodeBase);
  std::vector<std::uint8_t> mem(kMemSize, 0);
  const std::uint64_t value = 0x8765432112345678ULL;
  std::memcpy(mem.data() + 0x1f, &value, sizeof(value));
  auto actual = runLifted(code, regs, mem);
  REQUIRE(getReg64(actual.regs, x86off::RAX) == value);
  // The lifter pins RIP to the next instruction when computing an EA; the
  // fixture does not snapshot Unicorn RIP (nor define a post-RET RIP for JIT).
  REQUIRE(getReg64(actual.regs, 128) == kCodeBase + 8);
  setReg64(actual.regs, 128, 0);
  requireStatesMatch(runUnicorn(code, regs, mem), actual, regs);
}


TEST_CASE("Semantic round-trip - x64 GS read-modify-write uses segment base",
          "[semantic][x86_64][segment]") {
  // add qword ptr gs:[rcx],rdx; ret
  const std::vector<std::uint8_t> code = {0x65, 0x48, 0x01, 0x11, 0xc3};
  auto regs = defaultInitialRegs();
  setReg64(regs, x86off::GSBASE, kMemBase);
  setReg64(regs, x86off::RCX, 0x40);
  setReg64(regs, x86off::RDX, 5);
  std::vector<std::uint8_t> mem(kMemSize, 0);
  const std::uint64_t value = 0x7fffffffffffffffULL;
  std::memcpy(mem.data() + 0x40, &value, sizeof(value));
  requireStatesMatch(runUnicorn(code, regs, mem), runLifted(code, regs, mem), regs);
}

TEST_CASE("Semantic round-trip - x64 POP uses GS for destination not stack",
          "[semantic][x86_64][segment]") {
  // push rax; pop qword ptr gs:[rcx]; ret
  const std::vector<std::uint8_t> code = {0x50, 0x65, 0x8f, 0x01, 0xc3};
  auto regs = defaultInitialRegs();
  setReg64(regs, x86off::GSBASE, kMemBase);
  setReg64(regs, x86off::RCX, 0x60);
  setReg64(regs, x86off::RAX, 0x123456789abcdef0ULL);
  requireStatesMatch(runUnicorn(code, regs, {}), runLifted(code, regs, {}), regs);
}


TEST_CASE("Semantic round-trip - x64 PUSH memory reads before RSP update",
          "[semantic][x86_64][pushmem]") {
  // Only generated fixture bytes are executed, never the protected sample.
  std::vector<std::uint8_t> code = {0xff, 0x33, 0x58, 0xc3};
  auto regs = defaultInitialRegs();
  setReg64(regs, x86off::RBX, kMemBase + 0x60);
  unpackEflags(0xcd7, regs); // All seven modeled flags must survive PUSH/POP.
  std::uint64_t source = kMemBase + 0x60;
  SECTION("push [rbx] exact sample opcode") {}
  SECTION("push [rsp+8] uses original RSP") {
    code = {0xff, 0x74, 0x24, 0x08, 0x58, 0xc3};
    source = kDefaultSP + 8;
  }
  SECTION("push [rsp-8] source aliases destination") {
    code = {0xff, 0x74, 0x24, 0xf8, 0x58, 0xc3};
    source = kDefaultSP - 8;
  }
  SECTION("push [rbx+rsi*4+0x18] scaled-index source") {
    code = {0xff, 0x74, 0xb3, 0x18, 0x58, 0xc3};
    setReg64(regs, x86off::RBX, kMemBase);
    setReg64(regs, x86off::RSI, 0x10);
    source = kMemBase + 0x58;
  }
  SECTION("push gs:[rbx] applies GS only to source") {
    code = {0x65, 0xff, 0x33, 0x58, 0xc3};
    setReg64(regs, x86off::RBX, 0x60);
    setReg64(regs, x86off::GSBASE, kMemBase);
  }
  SECTION("push fs:[rbx] applies FS only to source") {
    code = {0x64, 0xff, 0x33, 0x58, 0xc3};
    setReg64(regs, x86off::RBX, 0x60);
    setReg64(regs, x86off::FSBASE, kMemBase);
  }
  SECTION("addr32 wraps before adding GS base") {
    code = {0x65, 0x67, 0xff, 0x73, 0x30, 0x58, 0xc3};
    setReg64(regs, x86off::RBX, 0x12345678ffffffe0ULL);
    setReg64(regs, x86off::GSBASE, kMemBase);
    source = kMemBase + 0x10;
  }
  const std::uint64_t value = 0xfedcba9876543210ULL;
  std::vector<std::uint8_t> mem(kMemSize, 0);
  std::memcpy(mem.data() + source - kMemBase, &value, sizeof(value));
  auto actual = runLifted(code, regs, mem);
  REQUIRE(getReg64(actual.regs, x86off::RAX) == value);
  // The comparison harness excludes RET's RSP increment on both sides.
  REQUIRE(getReg64(actual.regs, x86off::RSP) == kDefaultSP);
  requireStatesMatch(runUnicorn(code, regs, mem), actual, regs);
}
