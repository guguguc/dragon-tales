#include <catch2/catch_test_macros.hpp>

#include <dragon/lifters/ignil/IGNIL.hpp>
#include <dragon/lifters/ignil/IGNILSimplify.hpp>
#include <dragon/lifters/ignil/SymbolicExecutor.hpp>
#include <dragon/lifters/ignil/x86/x86IGNILRegs.hpp>

#include <algorithm>
#include <cstring>
#include <set>

namespace x86 = dragon::x86;
using dragon::ignil::Block;
using dragon::ignil::Const;
using dragon::ignil::ExecStatus;
using dragon::ignil::Opcode;
using dragon::ignil::RunResult;
using dragon::ignil::simplifyBlock;
using dragon::ignil::SymbolicExecutor;
using dragon::ignil::SymbolicOptions;
using dragon::ignil::Temp;
using dragon::ignil::Value;

namespace {

constexpr std::uint64_t kAddr = 0x1000;

/// Reinterpret a double's bits, the way IGNIL's float opcodes see them.
std::uint64_t bitsOf(double d) {
  std::uint64_t bits = 0;
  std::memcpy(&bits, &d, sizeof(bits));
  return bits;
}

double doubleOf(std::uint64_t bits) {
  double d = 0;
  std::memcpy(&d, &bits, sizeof(d));
  return d;
}

} // namespace

// ---------------------------------------------------------------------------
// Basic evaluation
// ---------------------------------------------------------------------------

TEST_CASE("SymbolicExecutor - concrete arithmetic evaluates to a constant",
          "[ignil][symbolic]") {
  // RAX = 5; RAX = RAX + 3
  Block block{kAddr};
  block.append({Opcode::COPY, Value{x86::RAX}, {Value{Const{5, 64}}}, kAddr});
  block.append({Opcode::ADD, Value{x86::RAX},
                {Value{x86::RAX}, Value{Const{3, 64}}}, kAddr + 4});
  block.append({Opcode::RET, std::nullopt, {}, kAddr + 8});

  SymbolicExecutor exec;
  RunResult r = exec.run(block);

  REQUIRE(r.ok());
  REQUIRE(r.exit == dragon::ignil::ExitKind::Return);
  REQUIRE(exec.evaluate(exec.readRegister(x86::RAX)) == 8);
}

TEST_CASE("SymbolicExecutor - a register that was never written is symbolic",
          "[ignil][symbolic]") {
  SymbolicExecutor exec;
  // No unique value: RBX can be anything.
  REQUIRE_FALSE(exec.evaluate(exec.readRegister(x86::RBX)).has_value());

  // ...unless the caller asks for a fully specified machine instead.
  SymbolicOptions opts;
  opts.symbolizeUnmappedReads = false;
  SymbolicExecutor zeroed{opts};
  REQUIRE(zeroed.evaluate(zeroed.readRegister(x86::RBX)) == 0);
}

TEST_CASE("SymbolicExecutor - seeded registers propagate through a block",
          "[ignil][symbolic]") {
  // RAX = RDI * RSI
  Block block{kAddr};
  block.append({Opcode::MUL, Value{x86::RAX},
                {Value{x86::RDI}, Value{x86::RSI}}, kAddr});

  SymbolicExecutor exec;
  exec.setRegister(x86::RDI, 7);
  exec.setRegister(x86::RSI, 6);
  REQUIRE(exec.run(block).ok());

  REQUIRE(exec.evaluate(exec.readRegister(x86::RAX)) == 42);
}

// ---------------------------------------------------------------------------
// Sub-register aliasing - the byte-granular register file
// ---------------------------------------------------------------------------

TEST_CASE("SymbolicExecutor - a 32-bit write clears the upper half",
          "[ignil][symbolic]") {
  Block block{kAddr};
  block.append({Opcode::COPY, Value{x86::EAX}, {Value{Const{0, 32}}}, kAddr});

  SymbolicExecutor exec;
  exec.setRegister(x86::RAX, 0x1122334455667788ull);
  REQUIRE(exec.run(block).ok());

  // `xor eax, eax` really does zero the whole of RAX.
  REQUIRE(exec.evaluate(exec.readRegister(x86::RAX)) == 0);
}

TEST_CASE("SymbolicExecutor - 8- and 16-bit writes merge into the parent",
          "[ignil][symbolic]") {
  SECTION("AL touches only byte 0") {
    Block block{kAddr};
    block.append({Opcode::COPY, Value{x86::AL}, {Value{Const{0xFF, 8}}}, kAddr});

    SymbolicExecutor exec;
    exec.setRegister(x86::RAX, 0x1122334455667788ull);
    REQUIRE(exec.run(block).ok());
    REQUIRE(exec.evaluate(exec.readRegister(x86::RAX)) == 0x11223344556677FFull);
  }

  SECTION("AH touches only byte 1") {
    Block block{kAddr};
    block.append({Opcode::COPY, Value{x86::AH}, {Value{Const{0xEE, 8}}}, kAddr});

    SymbolicExecutor exec;
    exec.setRegister(x86::RAX, 0x1122334455667788ull);
    REQUIRE(exec.run(block).ok());
    REQUIRE(exec.evaluate(exec.readRegister(x86::RAX)) == 0x112233445566EE88ull);
  }

  SECTION("AX touches only bytes 0-1") {
    Block block{kAddr};
    block.append({Opcode::COPY, Value{x86::AX}, {Value{Const{0xBEEF, 16}}},
                  kAddr});

    SymbolicExecutor exec;
    exec.setRegister(x86::RAX, 0x1122334455667788ull);
    REQUIRE(exec.run(block).ok());
    REQUIRE(exec.evaluate(exec.readRegister(x86::RAX)) == 0x112233445566BEEFull);
  }
}

TEST_CASE("SymbolicExecutor - sub-register reads slice the parent",
          "[ignil][symbolic]") {
  SymbolicExecutor exec;
  exec.setRegister(x86::RAX, 0x1122334455667788ull);

  REQUIRE(exec.evaluate(exec.readRegister(x86::EAX)) == 0x55667788u);
  REQUIRE(exec.evaluate(exec.readRegister(x86::AX)) == 0x7788u);
  REQUIRE(exec.evaluate(exec.readRegister(x86::AL)) == 0x88u);
  REQUIRE(exec.evaluate(exec.readRegister(x86::AH)) == 0x77u);
}

// ---------------------------------------------------------------------------
// Operation semantics
// ---------------------------------------------------------------------------

TEST_CASE("SymbolicExecutor - shifts match IGNILSimplify's constant folding",
          "[ignil][symbolic]") {
  // Both paths must agree: run the block symbolically, and fold it with
  // simplifyBlock. A disagreement means the executor and the folder model the
  // same opcode differently, which would make a simplified block behave
  // differently from the one it came from.
  struct Case {
    Opcode op;
    std::uint64_t lhs;
    std::uint64_t amount;
    dragon::ignil::Width width;
  };

  const Case cases[] = {
          {Opcode::SHL, 0xFF, 4, 8}, // in range
          {Opcode::SHL, 0xFF, 8, 8}, // amount == width
          {Opcode::SHL, 0xFF, 200, 8}, // amount past the width
          {Opcode::SHR, 0xFF, 4, 8},
          {Opcode::SHR, 0xFF, 200, 8},
          {Opcode::SAR, 0x80, 4, 8}, // negative, sign-fills
          {Opcode::SAR, 0x80, 200, 8}, // saturates to all-ones
          {Opcode::SAR, 0x7F, 200, 8}, // positive, saturates to zero
  };

  for (const Case &c : cases) {
    Block block{kAddr};
    block.append({c.op, Value{x86::AL},
                  {Value{Const{c.lhs, c.width}}, Value{Const{c.amount, 8}}},
                  kAddr});

    SymbolicExecutor exec;
    REQUIRE(exec.run(block).ok());
    const auto symbolic = exec.evaluate(exec.readRegister(x86::AL));
    REQUIRE(symbolic.has_value());

    Block folded = simplifyBlock(block);
    REQUIRE(folded.size() == 1);
    REQUIRE(folded.ops()[0].opcode == Opcode::COPY);
    REQUIRE(std::holds_alternative<Const>(folded.ops()[0].srcs[0]));
    REQUIRE(*symbolic == std::get<Const>(folded.ops()[0].srcs[0]).value);
  }
}

TEST_CASE("SymbolicExecutor - signed and unsigned division differ on the "
          "same bits",
          "[ignil][symbolic]") {
  const std::uint64_t minusEight = 0xFFFFFFFFFFFFFFF8ull;

  Block block{kAddr};
  block.append({Opcode::SDIV, Value{x86::RAX},
                {Value{Const{minusEight, 64}}, Value{Const{3, 64}}}, kAddr});
  block.append({Opcode::UDIV, Value{x86::RBX},
                {Value{Const{minusEight, 64}}, Value{Const{3, 64}}}, kAddr});
  block.append({Opcode::SMOD, Value{x86::RCX},
                {Value{Const{minusEight, 64}}, Value{Const{3, 64}}}, kAddr});

  SymbolicExecutor exec;
  REQUIRE(exec.run(block).ok());

  // -8 / 3 truncates toward zero, as C does.
  REQUIRE(exec.evaluate(exec.readRegister(x86::RAX)) == 0xFFFFFFFFFFFFFFFEull);
  REQUIRE(exec.evaluate(exec.readRegister(x86::RBX)) == (minusEight / 3));
  // -8 % 3 == -2: srem takes the sign of the dividend, unlike smod.
  REQUIRE(exec.evaluate(exec.readRegister(x86::RCX)) == 0xFFFFFFFFFFFFFFFEull);
}

TEST_CASE("SymbolicExecutor - comparisons produce a 1-bit result",
          "[ignil][symbolic]") {
  const std::uint64_t minusOne = 0xFFFFFFFFull;

  Block block{kAddr};
  Temp signedLt{0, 1};
  Temp unsignedLt{1, 1};
  // -1 < 1 signed, but 0xFFFFFFFF > 1 unsigned.
  block.append({Opcode::SLT, Value{signedLt},
                {Value{Const{minusOne, 32}}, Value{Const{1, 32}}}, kAddr});
  block.append({Opcode::ULT, Value{unsignedLt},
                {Value{Const{minusOne, 32}}, Value{Const{1, 32}}}, kAddr});

  SymbolicExecutor exec;
  REQUIRE(exec.run(block).ok());
  REQUIRE(exec.evaluate(*exec.readTemp(signedLt)) == 1);
  REQUIRE(exec.evaluate(*exec.readTemp(unsignedLt)) == 0);
}

TEST_CASE("SymbolicExecutor - SEXT and ZEXT widen differently",
          "[ignil][symbolic]") {
  Block block{kAddr};
  Temp narrow{0, 8};
  block.append({Opcode::COPY, Value{narrow}, {Value{Const{0x80, 8}}}, kAddr});
  block.append({Opcode::SEXT, Value{x86::RAX}, {Value{narrow}}, kAddr});
  block.append({Opcode::ZEXT, Value{x86::RBX}, {Value{narrow}}, kAddr});

  SymbolicExecutor exec;
  REQUIRE(exec.run(block).ok());
  REQUIRE(exec.evaluate(exec.readRegister(x86::RAX)) == 0xFFFFFFFFFFFFFF80ull);
  REQUIRE(exec.evaluate(exec.readRegister(x86::RBX)) == 0x80);
}

TEST_CASE("SymbolicExecutor - IEEE754 double arithmetic", "[ignil][symbolic]") {
  Block block{kAddr};
  block.append({Opcode::FADD, Value{x86::RAX},
                {Value{Const{bitsOf(1.5), 64}}, Value{Const{bitsOf(2.25), 64}}},
                kAddr});
  // Round-trip an integer through a double and back.
  block.append({Opcode::SITOFP, Value{x86::RBX}, {Value{Const{42, 64}}}, kAddr});
  block.append({Opcode::FPTOSI, Value{x86::RCX}, {Value{x86::RBX}}, kAddr});
  // Truncation toward zero, not rounding to nearest.
  block.append({Opcode::FPTOSI, Value{x86::RDX},
                {Value{Const{bitsOf(-3.9), 64}}}, kAddr});

  SymbolicExecutor exec;
  REQUIRE(exec.run(block).ok());

  const auto sum = exec.evaluate(exec.readRegister(x86::RAX));
  REQUIRE(sum.has_value());
  REQUIRE(doubleOf(*sum) == 3.75);

  REQUIRE(exec.evaluate(exec.readRegister(x86::RCX)) == 42);
  REQUIRE(exec.evaluate(exec.readRegister(x86::RDX)) ==
          0xFFFFFFFFFFFFFFFDull); // -3
}

// ---------------------------------------------------------------------------
// Memory
// ---------------------------------------------------------------------------

TEST_CASE("SymbolicExecutor - concrete blobs load little-endian",
          "[ignil][symbolic]") {
  SymbolicExecutor exec;
  exec.mapMemory(0x4000, {0x78, 0x56, 0x34, 0x12});

  REQUIRE(exec.evaluate(exec.readMemory(0x4000, 32)) == 0x12345678u);
  REQUIRE(exec.evaluate(exec.readMemory(0x4000, 8)) == 0x78);
  REQUIRE(exec.evaluate(exec.readMemory(0x4002, 16)) == 0x1234u);
}

TEST_CASE("SymbolicExecutor - a symbolic value survives a store/load round trip",
          "[ignil][symbolic]") {
  // [0x4000] = RDI ; RAX = [0x4000]
  Block block{kAddr};
  Temp addr{0, 64};
  block.append({Opcode::COPY, Value{addr}, {Value{Const{0x4000, 64}}}, kAddr});
  block.append({Opcode::STORE, std::nullopt, {Value{addr}, Value{x86::RDI}},
                kAddr});
  block.append({Opcode::LOAD, Value{x86::RAX}, {Value{addr}}, kAddr + 4});

  SymbolicExecutor exec;
  const z3::expr input = exec.symbolizeRegister(x86::RDI, "arg");
  REQUIRE(exec.run(block).ok());

  REQUIRE(exec.proves(exec.readRegister(x86::RAX) == input) == true);
}

TEST_CASE("SymbolicExecutor - a symbolic store address resolves to its "
          "candidates",
          "[ignil][symbolic]") {
  // [RDI] = 0xAA, where RDI is known to be either 0x100 or 0x200.
  Block block{kAddr};
  block.append({Opcode::STORE, std::nullopt,
                {Value{x86::RDI}, Value{Const{0xAA, 8}}}, kAddr});

  SymbolicExecutor exec;
  const z3::expr rdi = exec.symbolizeRegister(x86::RDI, "ptr");
  exec.assume(rdi == exec.bv(0x100, 64) || rdi == exec.bv(0x200, 64));
  exec.mapMemory(0x100, {0x00});
  exec.mapMemory(0x200, {0x00});

  RunResult r = exec.run(block);
  REQUIRE(r.complete());
  REQUIRE(r.stats.addressesConcretized == 2);

  // Neither byte is unconditionally 0xAA - each holds it only on the path
  // where RDI actually pointed there.
  REQUIRE_FALSE(exec.evaluate(exec.readMemory(0x100, 8)).has_value());
  REQUIRE(exec.proves(z3::implies(rdi == exec.bv(0x100, 64),
                                  exec.readMemory(0x100, 8) ==
                                          exec.bv(0xAA, 8))) == true);
  REQUIRE(exec.proves(z3::implies(rdi == exec.bv(0x200, 64),
                                  exec.readMemory(0x100, 8) ==
                                          exec.bv(0x00, 8))) == true);
}

TEST_CASE("SymbolicExecutor - an unconstrained store address is reported, "
          "not guessed",
          "[ignil][symbolic]") {
  Block block{kAddr};
  block.append({Opcode::STORE, std::nullopt,
                {Value{x86::RDI}, Value{Const{0xAA, 8}}}, kAddr});

  SymbolicExecutor exec;
  exec.symbolizeRegister(x86::RDI, "ptr"); // no constraint at all

  RunResult r = exec.run(block);
  REQUIRE(r.ok()); // execution continued
  REQUIRE_FALSE(r.complete()); // but the account is not complete
  REQUIRE(r.warnings.size() == 1);
  REQUIRE(r.warnings[0].address == kAddr);
}

// ---------------------------------------------------------------------------
// Proving identities - the MBA de-obfuscation case
// ---------------------------------------------------------------------------

TEST_CASE("SymbolicExecutor - proves mixed boolean-arithmetic identities",
          "[ignil][symbolic]") {
  SECTION("(a | b) + (a & b) == a + b") {
    Block block{kAddr};
    Temp orv{0, 64};
    Temp andv{1, 64};
    block.append({Opcode::OR, Value{orv}, {Value{x86::RDI}, Value{x86::RSI}},
                  kAddr});
    block.append({Opcode::AND, Value{andv}, {Value{x86::RDI}, Value{x86::RSI}},
                  kAddr});
    block.append({Opcode::ADD, Value{x86::RAX}, {Value{orv}, Value{andv}},
                  kAddr});

    SymbolicExecutor exec;
    const z3::expr a = exec.symbolizeRegister(x86::RDI, "a");
    const z3::expr b = exec.symbolizeRegister(x86::RSI, "b");
    REQUIRE(exec.run(block).ok());

    REQUIRE(exec.proves(exec.readRegister(x86::RAX) == a + b) == true);
  }

  SECTION("(a | b) - (a & b) == a ^ b") {
    Block block{kAddr};
    Temp orv{0, 64};
    Temp andv{1, 64};
    block.append({Opcode::OR, Value{orv}, {Value{x86::RDI}, Value{x86::RSI}},
                  kAddr});
    block.append({Opcode::AND, Value{andv}, {Value{x86::RDI}, Value{x86::RSI}},
                  kAddr});
    block.append({Opcode::SUB, Value{x86::RAX}, {Value{orv}, Value{andv}},
                  kAddr});

    SymbolicExecutor exec;
    const z3::expr a = exec.symbolizeRegister(x86::RDI, "a");
    const z3::expr b = exec.symbolizeRegister(x86::RSI, "b");
    REQUIRE(exec.run(block).ok());

    REQUIRE(exec.proves(exec.readRegister(x86::RAX) == (a ^ b)) == true);
  }

  SECTION("a false identity is refuted") {
    Block block{kAddr};
    block.append({Opcode::XOR, Value{x86::RAX},
                  {Value{x86::RDI}, Value{x86::RSI}}, kAddr});

    SymbolicExecutor exec;
    const z3::expr a = exec.symbolizeRegister(x86::RDI, "a");
    const z3::expr b = exec.symbolizeRegister(x86::RSI, "b");
    REQUIRE(exec.run(block).ok());

    REQUIRE(exec.proves(exec.readRegister(x86::RAX) == a + b) == false);
  }
}

TEST_CASE("SymbolicExecutor - recovers the constant an obfuscated block "
          "actually computes",
          "[ignil][symbolic]") {
  // ((x ^ 0xA5A5) + 0xA5A5) - (x ^ 0xA5A5) is x-independent: it is 0xA5A5.
  Block block{kAddr};
  Temp masked{0, 64};
  Temp shifted{1, 64};
  block.append({Opcode::XOR, Value{masked},
                {Value{x86::RDI}, Value{Const{0xA5A5, 64}}}, kAddr});
  block.append({Opcode::ADD, Value{shifted},
                {Value{masked}, Value{Const{0xA5A5, 64}}}, kAddr});
  block.append({Opcode::SUB, Value{x86::RAX}, {Value{shifted}, Value{masked}},
                kAddr});

  SymbolicExecutor exec;
  exec.symbolizeRegister(x86::RDI, "x");
  REQUIRE(exec.run(block).ok());

  REQUIRE(exec.evaluate(exec.readRegister(x86::RAX)) == 0xA5A5);
}

// ---------------------------------------------------------------------------
// Solving - the CTF case
// ---------------------------------------------------------------------------

TEST_CASE("SymbolicExecutor - recovers the key of an XOR crackme",
          "[ignil][symbolic][ctf]") {
  // The classic shape: the flag buffer is XORed with a constant and compared
  // against a hardcoded blob. Symbolise the buffer, assert the comparison
  // succeeded, and read the flag out of the model.
  constexpr std::uint64_t kBuffer = 0x4000;
  constexpr std::uint64_t kKey = 0x5A5A5A5A5A5A5A5Aull;
  const char *secret = "DRAGON!!";

  std::uint64_t expected = 0;
  std::memcpy(&expected, secret, 8);
  expected ^= kKey;

  Block block{kAddr};
  Temp addr{0, 64};
  Temp loaded{1, 64};
  block.append({Opcode::COPY, Value{addr}, {Value{Const{kBuffer, 64}}}, kAddr});
  block.append({Opcode::LOAD, Value{loaded}, {Value{addr}}, kAddr});
  block.append({Opcode::XOR, Value{x86::RAX},
                {Value{loaded}, Value{Const{kKey, 64}}}, kAddr});

  SymbolicExecutor exec;
  exec.symbolizeMemory(kBuffer, 8, "flag");
  REQUIRE(exec.run(block).ok());

  auto solution = exec.solve(exec.readRegister(x86::RAX) == exec.bv(expected, 64));
  REQUIRE(solution.has_value());

  const std::vector<std::uint8_t> flag = solution->bytes("flag");
  REQUIRE(flag.size() == 8);
  REQUIRE(std::string(flag.begin(), flag.end()) == secret);
}

TEST_CASE("SymbolicExecutor - inverts an FNV-1a hash under a charset "
          "constraint",
          "[ignil][symbolic][ctf]") {
  // A "check(input) == magic" challenge: four bytes of input are folded into
  // an FNV-1a digest. There is no closed form to invert, so the solver has to
  // search - which is the point.
  constexpr std::uint64_t kBuffer = 0x5000;
  constexpr std::uint32_t kBasis = 0x811C9DC5u;
  constexpr std::uint32_t kPrime = 0x01000193u;
  constexpr std::size_t kLen = 4;

  const auto fnv1a = [](const std::vector<std::uint8_t> &data) {
    std::uint32_t h = kBasis;
    for (std::uint8_t b : data) {
      h ^= b;
      h *= kPrime;
    }
    return h;
  };

  const std::vector<std::uint8_t> target = {'l', '3', '3', 't'};
  const std::uint32_t digest = fnv1a(target);

  // h = basis; for each byte: h = (h ^ byte) * prime
  Block block{kAddr};
  block.append({Opcode::COPY, Value{x86::EAX}, {Value{Const{kBasis, 32}}},
                kAddr});
  std::uint32_t temp = 0;
  for (std::size_t i = 0; i < kLen; ++i) {
    Temp byteAddr{temp++, 64};
    Temp byte{temp++, 8};
    Temp wide{temp++, 32};
    Temp mixed{temp++, 32};

    block.append({Opcode::COPY, Value{byteAddr},
                  {Value{Const{kBuffer + i, 64}}}, kAddr});
    block.append({Opcode::LOAD, Value{byte}, {Value{byteAddr}}, kAddr});
    block.append({Opcode::ZEXT, Value{wide}, {Value{byte}}, kAddr});
    block.append({Opcode::XOR, Value{mixed}, {Value{x86::EAX}, Value{wide}},
                  kAddr});
    block.append({Opcode::MUL, Value{x86::EAX},
                  {Value{mixed}, Value{Const{kPrime, 32}}}, kAddr});
  }

  SymbolicExecutor exec;
  exec.symbolizeMemory(kBuffer, kLen, "input");

  // Printable ASCII only, or the solver is free to return any of the many
  // preimages a 32-bit digest has.
  for (std::size_t i = 0; i < kLen; ++i) {
    const z3::expr b = exec.readMemory(kBuffer + i, 8);
    exec.assume(z3::uge(b, exec.bv(0x21, 8)));
    exec.assume(z3::ule(b, exec.bv(0x7E, 8)));
  }

  REQUIRE(exec.run(block).ok());

  auto solution = exec.solve(exec.readRegister(x86::EAX) == exec.bv(digest, 32));
  REQUIRE(solution.has_value());

  // The solver may legitimately find a different preimage than the one the
  // digest came from - what has to hold is that it hashes to the target.
  const std::vector<std::uint8_t> recovered = solution->bytes("input");
  REQUIRE(recovered.size() == kLen);
  REQUIRE(fnv1a(recovered) == digest);
  for (std::uint8_t b : recovered)
    REQUIRE((b >= 0x21 && b <= 0x7E));
}

TEST_CASE("SymbolicExecutor - reports an unsatisfiable goal instead of "
          "inventing an answer",
          "[ignil][symbolic][ctf]") {
  // RAX = RDI * 2 can never be odd.
  Block block{kAddr};
  block.append({Opcode::MUL, Value{x86::RAX},
                {Value{x86::RDI}, Value{Const{2, 64}}}, kAddr});

  SymbolicExecutor exec;
  exec.symbolizeRegister(x86::RDI, "x");
  REQUIRE(exec.run(block).ok());

  REQUIRE_FALSE(
          exec.solve(exec.readRegister(x86::RAX) == exec.bv(7, 64)).has_value());
  REQUIRE(exec.solve(exec.readRegister(x86::RAX) == exec.bv(8, 64)).has_value());
}

// ---------------------------------------------------------------------------
// Interaction with the IGNIL optimisation passes
// ---------------------------------------------------------------------------

TEST_CASE("SymbolicExecutor - simplifying a block first does not change what "
          "it computes",
          "[ignil][symbolic][simplify]") {
  // Deliberately full of things simplifyBlock will fold away: an identity
  // add, a redundant copy chain, an annihilating AND, and a dead temp.
  Block block{kAddr};
  Temp t0{0, 64};
  Temp t1{1, 64};
  Temp t2{2, 64};
  Temp dead{3, 64};
  block.append({Opcode::COPY, Value{t0}, {Value{x86::RDI}}, kAddr});
  block.append({Opcode::ADD, Value{t1}, {Value{t0}, Value{Const{0, 64}}},
                kAddr});
  block.append({Opcode::AND, Value{dead}, {Value{t1}, Value{Const{0, 64}}},
                kAddr});
  block.append({Opcode::MUL, Value{t2}, {Value{t1}, Value{Const{3, 64}}},
                kAddr});
  block.append({Opcode::ADD, Value{x86::RAX}, {Value{t2}, Value{Const{7, 64}}},
                kAddr});

  dragon::ignil::SimplifyStats stats;
  const Block folded = simplifyBlock(block, stats);
  REQUIRE(stats.changed());
  REQUIRE(folded.size() < block.size());

  const auto resultOf = [](const Block &b) {
    SymbolicExecutor exec;
    exec.symbolizeRegister(x86::RDI, "x");
    REQUIRE(exec.run(b).ok());
    // 3x + 7, whichever block computed it.
    const z3::expr x = exec.state().symbols().at("x");
    return exec.proves(exec.readRegister(x86::RAX) ==
                       x * exec.bv(3, 64) + exec.bv(7, 64));
  };

  REQUIRE(resultOf(block) == true);
  REQUIRE(resultOf(folded) == true);
}

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

TEST_CASE("SymbolicExecutor - rejects malformed ops rather than guessing",
          "[ignil][symbolic]") {
  SECTION("binary op with one source") {
    Block block{kAddr};
    block.append({Opcode::ADD, Value{x86::RAX}, {Value{Const{1, 64}}}, kAddr});

    SymbolicExecutor exec;
    RunResult r = exec.run(block);
    REQUIRE(r.status == ExecStatus::MalformedOp);
    REQUIRE(r.exit == dragon::ignil::ExitKind::Error);
    REQUIRE(r.error.find("ADD") != std::string::npos);
  }

  SECTION("arithmetic with no destination") {
    Block block{kAddr};
    block.append({Opcode::ADD, std::nullopt,
                  {Value{Const{1, 64}}, Value{Const{2, 64}}}, kAddr});

    SymbolicExecutor exec;
    REQUIRE(exec.run(block).status == ExecStatus::MalformedOp);
  }
}

// ---------------------------------------------------------------------------
// Snapshot / restore and state diffing
// ---------------------------------------------------------------------------

using Delta = dragon::ignil::SymbolicState::Delta;

namespace {

/// The one delta covering `key`, or nullptr.
const Delta *deltaAt(const std::vector<Delta> &ds, Delta::Kind kind,
                     std::uint64_t key) {
  for (const Delta &d : ds)
    if (d.kind == kind && d.key == key)
      return &d;
  return nullptr;
}

} // namespace

TEST_CASE("SymbolicExecutor - a state snapshot can be restored",
          "[ignil][symbolic][diff]") {
  SymbolicExecutor exec;
  exec.setRegister(x86::RAX, 0x1000);
  const dragon::ignil::SymbolicState before = exec.state();

  Block block{kAddr};
  block.append({Opcode::ADD,
                Value{x86::RAX},
                {Value{x86::RAX}, Value{Const{0x24, 64}}},
                kAddr});
  REQUIRE(exec.run(block).ok());
  REQUIRE(exec.evaluate(exec.readRegister(x86::RAX)) == 0x1024);

  exec.setState(before);
  REQUIRE(exec.evaluate(exec.readRegister(x86::RAX)) == 0x1000);

  // ... and the restored state is a starting point again, not a dead end.
  REQUIRE(exec.run(block).ok());
  REQUIRE(exec.evaluate(exec.readRegister(x86::RAX)) == 0x1024);
}

TEST_CASE("SymbolicExecutor - diff reports what a block changed, whole values "
          "rather than bytes",
          "[ignil][symbolic][diff]") {
  SymbolicExecutor exec;
  exec.setRegister(x86::RBX, 0x4000);
  const dragon::ignil::SymbolicState before = exec.state();

  SECTION("an unchanged state has no deltas") {
    REQUIRE(exec.diff(before).empty());
  }

  SECTION("one 64-bit register write is one 64-bit delta") {
    Block block{kAddr};
    block.append({Opcode::COPY, Value{x86::RAX}, {Value{Const{0x1122334455667788, 64}}},
                  kAddr});
    REQUIRE(exec.run(block).ok());

    const auto ds = exec.diff(before);
    REQUIRE(ds.size() == 1);
    const Delta *d = deltaAt(ds, Delta::Kind::Register, x86::RAX.offset);
    REQUIRE(d != nullptr);
    REQUIRE(d->width == 64);
    REQUIRE(exec.evaluate(d->value) == 0x1122334455667788);
  }

  SECTION("a store is reported at the address and width it was written") {
    Block block{kAddr};
    block.append({Opcode::STORE, std::nullopt,
                  {Value{x86::RBX}, Value{Const{0xdeadbeef, 32}}}, kAddr});
    REQUIRE(exec.run(block).ok());

    const auto ds = exec.diff(before);
    REQUIRE(ds.size() == 1);
    const Delta *d = deltaAt(ds, Delta::Kind::Memory, 0x4000);
    REQUIRE(d != nullptr);
    REQUIRE(d->width == 32);
    REQUIRE(exec.evaluate(d->value) == 0xdeadbeef);
  }

  SECTION("a sub-register write is reported at its own width, not the parent's") {
    Block block{kAddr};
    block.append({Opcode::COPY, Value{x86::AL}, {Value{Const{0x5a, 8}}}, kAddr});
    REQUIRE(exec.run(block).ok());

    const auto ds = exec.diff(before);
    REQUIRE(ds.size() == 1);
    const Delta *d = deltaAt(ds, Delta::Kind::Register, x86::AL.offset);
    REQUIRE(d != nullptr);
    REQUIRE(d->width == 8);
    REQUIRE(exec.evaluate(d->value) == 0x5a);
  }

  SECTION("a symbolic value survives the diff as an expression") {
    const z3::expr in = exec.symbolizeRegister(x86::RCX, "in");
    const dragon::ignil::SymbolicState seeded = exec.state();

    Block block{kAddr};
    block.append({Opcode::ADD,
                  Value{x86::RAX},
                  {Value{x86::RCX}, Value{Const{7, 64}}},
                  kAddr});
    REQUIRE(exec.run(block).ok());

    const auto ds = exec.diff(seeded);
    REQUIRE(ds.size() == 1);
    const Delta *d = deltaAt(ds, Delta::Kind::Register, x86::RAX.offset);
    REQUIRE(d != nullptr);
    REQUIRE(d->width == 64);
    REQUIRE(exec.proves(d->value == in + 7).value_or(false));
  }
}

// ---------------------------------------------------------------------------
// OPAQUE: instructions IGNIL names but cannot express
// ---------------------------------------------------------------------------

using dragon::ignil::makeOpaqueAux;
using dragon::ignil::OpaqueKind;

TEST_CASE("SymbolicExecutor - a pure OPAQUE is a function of its operands",
          "[ignil][symbolic][opaque]") {
  // Two CPUIDs with the same leaf must agree; with different leaves they must
  // not be forced to. That is the whole difference from UNDEF, which would
  // make all four of these unrelated unknowns.
  Block block{kAddr};
  block.append({Opcode::OPAQUE, Value{x86::EAX}, {Value{Const{1, 32}}}, kAddr,
                makeOpaqueAux(OpaqueKind::CPUID, 0)});
  block.append({Opcode::OPAQUE, Value{x86::EBX}, {Value{Const{1, 32}}}, kAddr + 2,
                makeOpaqueAux(OpaqueKind::CPUID, 0)});
  block.append({Opcode::OPAQUE, Value{x86::ECX}, {Value{Const{7, 32}}}, kAddr + 4,
                makeOpaqueAux(OpaqueKind::CPUID, 0)});

  SymbolicExecutor exec;
  REQUIRE(exec.run(block).ok());

  const z3::expr a = exec.readRegister(x86::EAX);
  const z3::expr b = exec.readRegister(x86::EBX);
  const z3::expr c = exec.readRegister(x86::ECX);

  // Same leaf, same result - even though the two ops are at different addresses.
  REQUIRE(exec.proves(a == b).value_or(false));
  // Different leaf: the solver must be free to disagree.
  REQUIRE(exec.isSatisfiable(c != a).value_or(false));
}

TEST_CASE("SymbolicExecutor - an impure OPAQUE is a fresh reading each time",
          "[ignil][symbolic][opaque]") {
  // Two RDTSCs are two separate events: nothing may prove them equal, or a
  // consumer would fold a timing check away.
  Block block{kAddr};
  block.append({Opcode::OPAQUE, Value{x86::EAX}, {}, kAddr,
                makeOpaqueAux(OpaqueKind::RDTSC, 0)});
  block.append({Opcode::OPAQUE, Value{x86::EBX}, {}, kAddr + 2,
                makeOpaqueAux(OpaqueKind::RDTSC, 0)});

  SymbolicOptions opts;
  opts.useHostTimestamps = false;
  SymbolicExecutor exec{opts};
  REQUIRE(exec.run(block).ok());

  const z3::expr a = exec.readRegister(x86::EAX);
  const z3::expr b = exec.readRegister(x86::EBX);
  REQUIRE_FALSE(exec.proves(a == b).value_or(true));
  REQUIRE(exec.isSatisfiable(a != b).value_or(false));
}

TEST_CASE("SymbolicExecutor - OPAQUE rejects a result index the kind has not got",
          "[ignil][symbolic][opaque]") {
  Block block{kAddr};
  // RDTSC defines two results; index 2 does not exist.
  block.append({Opcode::OPAQUE, Value{x86::EAX}, {}, kAddr,
                makeOpaqueAux(OpaqueKind::RDTSC, 2)});

  SymbolicExecutor exec;
  REQUIRE(exec.run(block).status == ExecStatus::MalformedOp);
}

TEST_CASE("SymbolicExecutor - a registered concrete OPAQUE returns literals",
          "[ignil][symbolic][opaque]") {
  // setConcreteOpaque makes a CPUID with a matching leaf/subleaf return fixed
  // literals, so a concolic trace never goes symbolic on an anti-tamper CPUID.
  // The four results land in EAX/EBX/ECX/EDX by result index.
  Block block{kAddr};
  const std::uint64_t leaf = 1, sub = 0;
  for (unsigned i = 0; i < 4; ++i)
    block.append({Opcode::OPAQUE,
                  Value{i == 0 ? x86::EAX : i == 1 ? x86::EBX
                               : i == 2 ? x86::ECX : x86::EDX},
                  {Value{Const{leaf, 32}}, Value{Const{sub, 32}}}, kAddr + 2 * i,
                  makeOpaqueAux(OpaqueKind::CPUID, i)});
  // A second, unregistered leaf must stay symbolic (falls through).
  block.append({Opcode::OPAQUE, Value{x86::ESI}, {Value{Const{7, 32}}, Value{Const{0, 32}}},
                kAddr + 8, makeOpaqueAux(OpaqueKind::CPUID, 0)});

  SymbolicExecutor exec;
  exec.setConcreteOpaque(
      OpaqueKind::CPUID,
      SymbolicExecutor::packConcreteOpaqueSelector(leaf, sub),
      {0x000906E9, 0x00100800, 0x7FFAFBFF, 0xBFEBFBFF});
  REQUIRE(exec.run(block).ok());

  // Each registered lane is a forced literal - evaluate() returns exactly one
  // value, which is the "did the obfuscation compute a constant?" query.
  REQUIRE(exec.evaluate(exec.readRegister(x86::EAX)) == 0x000906E9u);
  REQUIRE(exec.evaluate(exec.readRegister(x86::EBX)) == 0x00100800u);
  REQUIRE(exec.evaluate(exec.readRegister(x86::ECX)) == 0x7FFAFBFFu);
  REQUIRE(exec.evaluate(exec.readRegister(x86::EDX)) == 0xBFEBFBFFu);
  // The unregistered leaf has no single forced value.
  REQUIRE_FALSE(exec.evaluate(exec.readRegister(x86::ESI)).has_value());
}

TEST_CASE("SymbolicExecutor - CPUID leaf one ignores a symbolic ECX input",
          "[ignil][symbolic][opaque]") {
  SymbolicExecutor exec;
  exec.symbolizeRegister(x86::R10D, "cpuid.ecx.input");
  exec.setConcreteOpaque(OpaqueKind::CPUID,
      SymbolicExecutor::packConcreteOpaqueSelector(1, 0), {11, 22, 33, 44});
  Block block{kAddr};
  for (unsigned i = 0; i < 4; ++i)
    block.append({Opcode::OPAQUE,
        Value{i == 0 ? x86::EAX : i == 1 ? x86::EBX : i == 2 ? x86::ECX : x86::EDX},
        {Value{Const{1, 32}}, Value{x86::R10D}}, kAddr + i,
        makeOpaqueAux(OpaqueKind::CPUID, i)});
  REQUIRE(exec.run(block).ok());
  REQUIRE(exec.evaluate(exec.readRegister(x86::EAX)) == 11);
  REQUIRE(exec.evaluate(exec.readRegister(x86::EBX)) == 22);
  REQUIRE(exec.evaluate(exec.readRegister(x86::ECX)) == 33);
  REQUIRE(exec.evaluate(exec.readRegister(x86::EDX)) == 44);
}

TEST_CASE("SymbolicExecutor - unknown CPUID leaf one is ECX independent",
          "[ignil][symbolic][opaque]") {
  SymbolicExecutor exec;
  exec.symbolizeRegister(x86::R10D, "cpuid.ecx.input");
  Block block{kAddr};
  block.append({Opcode::OPAQUE, Value{x86::EAX},
      {Value{Const{1, 32}}, Value{x86::R10D}}, kAddr, makeOpaqueAux(OpaqueKind::CPUID, 0)});
  block.append({Opcode::OPAQUE, Value{x86::EBX},
      {Value{Const{1, 32}}, Value{Const{0xffffffff, 32}}}, kAddr + 1, makeOpaqueAux(OpaqueKind::CPUID, 0)});
  REQUIRE(exec.run(block).ok());
  REQUIRE(exec.proves(exec.readRegister(x86::EAX) == exec.readRegister(x86::EBX)).value_or(false));
  REQUIRE_FALSE(exec.evaluate(exec.readRegister(x86::EAX)).has_value());
}

TEST_CASE("SymbolicExecutor - indexed CPUID leaves retain the ECX input",
          "[ignil][symbolic][opaque]") {
  SymbolicExecutor exec;
  exec.symbolizeRegister(x86::R10D, "cpuid.ecx.input");
  exec.setConcreteOpaque(OpaqueKind::CPUID,
      SymbolicExecutor::packConcreteOpaqueSelector(7, 0), {11, 22, 33, 44});
  Block block{kAddr};
  block.append({Opcode::OPAQUE, Value{x86::EAX},
      {Value{Const{7, 32}}, Value{x86::R10D}}, kAddr, makeOpaqueAux(OpaqueKind::CPUID, 0)});
  block.append({Opcode::OPAQUE, Value{x86::EBX},
      {Value{Const{7, 32}}, Value{Const{1, 32}}}, kAddr + 1, makeOpaqueAux(OpaqueKind::CPUID, 0)});
  REQUIRE(exec.run(block).ok());
  REQUIRE_FALSE(exec.evaluate(exec.readRegister(x86::EAX)).has_value());
  REQUIRE_FALSE(exec.evaluate(exec.readRegister(x86::EBX)).has_value());
  REQUIRE(exec.isSatisfiable(exec.readRegister(x86::EAX) != exec.readRegister(x86::EBX)).value_or(false));
}

TEST_CASE("SymbolicExecutor - a restored snapshot is equivalent to a fresh "
          "executor, not merely similar",
          "[ignil][symbolic][diff]") {
  // The property that makes seed-once/restore a safe substitute for building a
  // fresh executor per block: after restoring, running a block must produce the
  // *same values* as running it on a freshly seeded machine - even though the
  // shared executor's Z3 context has already built terms for earlier blocks.
  //
  // Equality is asserted through the solver, not by comparing printed strings.
  // Z3 labels its let-bindings (a!1, a!2, ...) from per-context state, so a
  // context that has already processed other blocks prints an equal term
  // differently. That is cosmetic, but it means to_string() comparison is not
  // a correctness test - it reports false failures.
  auto seed = [](SymbolicExecutor &ex) {
    ex.symbolizeRegister(x86::RDI, "in");
    ex.symbolizeRegister(x86::RSI, "n");
    ex.setRegister(x86::RAX, 0);
  };
  auto work = [](std::uint64_t at) {
    Block b{at};
    // Enough structure that the printed form has let-bindings at all.
    b.append({Opcode::XOR, Value{x86::RAX}, {Value{x86::RDI}, Value{x86::RSI}}, at});
    b.append({Opcode::SHL, Value{x86::RBX}, {Value{x86::RAX}, Value{Const{4, 64}}}, at});
    b.append({Opcode::ADD, Value{x86::RCX}, {Value{x86::RBX}, Value{x86::RDI}}, at});
    return b;
  };

  const Block earlier = work(0x1000);
  const Block target = work(0x2000);

  // Shared executor: seed, snapshot, run something else, rewind, run target.
  SymbolicExecutor shared;
  seed(shared);
  const dragon::ignil::SymbolicState snap = shared.state();
  REQUIRE(shared.run(earlier).ok());
  shared.setState(snap);
  REQUIRE(shared.run(target).ok());

  // Fresh executor: seed, run target.
  SymbolicExecutor fresh;
  seed(fresh);
  REQUIRE(fresh.run(target).ok());

  // Compare inside one executor: rebuild the fresh result's defining equation
  // over the same symbols and let the solver decide.
  for (const auto &reg: {x86::RAX, x86::RBX, x86::RCX}) {
    const z3::expr a = shared.readRegister(reg);
    // in ^ n, shifted and added exactly as the block does.
    const z3::expr in = shared.state().symbol("in", 64);
    const z3::expr n = shared.state().symbol("n", 64);
    const z3::expr x = in ^ n;
    const z3::expr expected = reg.offset == x86::RAX.offset  ? x
                              : reg.offset == x86::RBX.offset ? z3::shl(x, 4)
                                                             : z3::shl(x, 4) + in;
    REQUIRE(shared.proves(a == expected).value_or(false));
  }

  // And the diff of the restored run sees exactly the three registers it wrote.
  const auto ds = shared.diff(snap);
  std::set<std::uint64_t> keys;
  for (const auto &d: ds)
    if (d.kind == dragon::ignil::SymbolicState::Delta::Kind::Register)
      keys.insert(d.key);
  REQUIRE(keys.count(x86::RAX.offset) == 1);
  REQUIRE(keys.count(x86::RBX.offset) == 1);
  REQUIRE(keys.count(x86::RCX.offset) == 1);
}

// ---------------------------------------------------------------------------
// Concrete images, the concrete fast path, merging, unresolved accesses
// ---------------------------------------------------------------------------

TEST_CASE("SymbolicExecutor - a large concrete blob is a shared image with a "
          "byte overlay on top",
          "[ignil][symbolic]") {
  using dragon::ignil::SymbolicState;

  std::vector<std::uint8_t> blob(4096);
  for (std::size_t i = 0; i < blob.size(); ++i)
    blob[i] = static_cast<std::uint8_t>(i);
  REQUIRE(blob.size() >= SymbolicState::kImageThreshold);

  SymbolicExecutor exec;
  exec.mapMemory(0x10000, blob);

  // Reads come back as literals, at any width, without touching the solver.
  REQUIRE(exec.readMemory(0x10010, 8).is_numeral());
  REQUIRE(exec.evaluate(exec.readMemory(0x10010, 64)) == 0x1716151413121110ull);
  REQUIRE(exec.state().isMemoryDefined(0x10ff8, 64));
  REQUIRE_FALSE(exec.state().isMemoryDefined(0x10ffc, 64)); // runs off the end

  // A write lands in the overlay and shadows the image under it...
  exec.setMemory(0x10012, exec.bv(0xAABB, 16));
  REQUIRE(exec.evaluate(exec.readMemory(0x10010, 64)) == 0x17161514AABB1110ull);

  // ...and a snapshot taken before it still sees the image's own bytes.
  SymbolicExecutor other;
  other.mapMemory(0x10000, blob);
  const SymbolicState before = other.state();
  other.setMemory(0x10012, other.bv(0xAABB, 16));
  REQUIRE(before.readMemory(0x10012, 16).is_numeral());
  REQUIRE(before.readMemory(0x10012, 16).get_numeral_uint64() == 0x1312);

  // Mapping over an overlay replaces it.
  exec.mapMemory(0x10000, blob);
  REQUIRE(exec.evaluate(exec.readMemory(0x10012, 16)) == 0x1312);
}

TEST_CASE("SymbolicExecutor - ops on literals fold instead of growing a term",
          "[ignil][symbolic]") {
  // RAX = ((RAX + 1) ^ RBX) << 3, a thousand times over, all concrete.
  Block block{kAddr};
  block.append({Opcode::ADD, Value{x86::RAX},
                {Value{x86::RAX}, Value{Const{1, 64}}}, kAddr});
  block.append({Opcode::XOR, Value{x86::RAX},
                {Value{x86::RAX}, Value{x86::RBX}}, kAddr + 4});
  block.append({Opcode::SHL, Value{x86::RAX},
                {Value{x86::RAX}, Value{Const{3, 64}}}, kAddr + 8});

  SymbolicExecutor exec;
  exec.setRegister(x86::RAX, 7);
  exec.setRegister(x86::RBX, 0x55);

  std::uint64_t expected = 7;
  for (int i = 0; i < 1000; ++i) {
    REQUIRE(exec.run(block).ok());
    expected = ((expected + 1) ^ 0x55) << 3;
  }

  const z3::expr rax = exec.readRegister(x86::RAX);
  REQUIRE(rax.is_numeral()); // a literal, not a 3000-node term
  REQUIRE(rax.get_numeral_uint64() == expected);
}

TEST_CASE("SymbolicState - merge turns what two paths disagree on into "
          "variables, whole values at a time, and converges",
          "[ignil][symbolic]") {
  using dragon::ignil::SymbolicState;
  using Kind = SymbolicState::Delta::Kind;

  SymbolicExecutor exec;
  exec.setRegister(x86::RAX, 1);            // differs between the paths
  exec.setRegister(x86::RBX, 7);            // same on both
  exec.setMemory(0x5000, exec.bv(0, 64));   // differs
  exec.setMemory(0x6000, exec.bv(9, 64));   // same
  SymbolicState joined = exec.state();

  exec.setRegister(x86::RAX, 2);
  exec.setMemory(0x5000, exec.bv(5, 64));

  auto changed = joined.merge(exec.state(), "loop");
  REQUIRE(changed.size() == 2);
  // One differing byte of a 64-bit value symbolises the whole value.
  REQUIRE(changed[0].kind == Kind::Register);
  REQUIRE(changed[0].key == x86::RAX.offset);
  REQUIRE(changed[0].width == 64);
  REQUIRE(changed[1].kind == Kind::Memory);
  REQUIRE(changed[1].key == 0x5000);
  REQUIRE(changed[1].width == 64);

  // What they agreed on is untouched; what they did not is a free variable.
  REQUIRE(joined.readRegister(x86::RBX).is_numeral());
  REQUIRE(joined.readMemory(0x6000, 64).is_numeral());
  REQUIRE_FALSE(joined.readRegister(x86::RAX).is_numeral());
  REQUIRE(joined.readRegister(x86::RAX).id() == changed[0].value.id());

  // The same state again adds nothing: that is the fixed point.
  REQUIRE(joined.merge(exec.state(), "loop").empty());
  // A third value for something already symbolised adds nothing either.
  exec.setRegister(x86::RAX, 3);
  REQUIRE(joined.merge(exec.state(), "loop").empty());

  // The loop's exit test, provably false while the counter was the literal 1,
  // is open again: both outcomes are satisfiable.
  exec.setState(joined);
  const z3::expr rax = exec.readRegister(x86::RAX);
  REQUIRE(exec.isSatisfiable(rax == exec.bv(10, 64)) == true);
  REQUIRE(exec.isSatisfiable(rax != exec.bv(10, 64)) == true);
}

TEST_CASE("SymbolicState - merge compares an overlay byte with the image "
          "byte under the other state",
          "[ignil][symbolic]") {
  using dragon::ignil::SymbolicState;

  std::vector<std::uint8_t> blob(512, 0x11);
  SymbolicExecutor exec;
  exec.mapMemory(0x8000, blob);
  SymbolicState joined = exec.state();

  // Rewriting the value the image already holds is not a disagreement.
  exec.setMemory(0x8010, exec.bv(0x1111111111111111ull, 64));
  REQUIRE(joined.merge(exec.state(), "n").empty());

  exec.setMemory(0x8010, exec.bv(0x2222222222222222ull, 64));
  auto changed = joined.merge(exec.state(), "n");
  REQUIRE(changed.size() == 1);
  REQUIRE(changed[0].key == 0x8010);
  REQUIRE(changed[0].width == 64);
}

TEST_CASE("SymbolicExecutor - an access through an unconstrained pointer is "
          "reported, not just dropped",
          "[ignil][symbolic]") {
  // t0 = LOAD(RDI); STORE(RSI, t0)  with RDI and RSI free
  Block block{kAddr};
  Temp t0{0, 64};
  block.append({Opcode::LOAD, Value{t0}, {Value{x86::RDI}}, kAddr});
  block.append({Opcode::STORE, std::nullopt, {Value{x86::RSI}, Value{t0}},
                kAddr + 4});

  SymbolicOptions opts;
  opts.maxAddressSolutions = 4;
  SymbolicExecutor exec(opts);
  const z3::expr src = exec.symbolizeRegister(x86::RDI, "src");
  const z3::expr dst = exec.symbolizeRegister(x86::RSI, "dst");
  exec.setFreshTag("ctx");

  RunResult r = exec.run(block);
  REQUIRE(r.ok());
  REQUIRE_FALSE(r.complete());
  REQUIRE(r.unresolved.size() == 2);

  REQUIRE_FALSE(r.unresolved[0].isStore);
  REQUIRE(r.unresolved[0].width == 64);
  REQUIRE(r.unresolved[0].address.id() == src.id());
  // The stand-in for the loaded value carries the tag, so the same block run
  // in another context gets a different variable.
  REQUIRE(r.unresolved[0].value.to_string().find("#ctx") != std::string::npos);

  REQUIRE(r.unresolved[1].isStore);
  REQUIRE(r.unresolved[1].address.id() == dst.id());
  REQUIRE(r.unresolved[1].value.id() == r.unresolved[0].value.id());
}


TEST_CASE("SymbolicExecutor - native host timestamp is the default and paired",
          "[ignil][symbolic][opaque][host-tsc]") {
#if !defined(__x86_64__) && !defined(__i386__) && !defined(_M_X64) &&          \
        !defined(_M_IX86)
  SKIP("native x86 timestamp test requires an x86 host");
#endif
  Block block{kAddr};
  block.append({Opcode::OPAQUE,
                Value{x86::EAX},
                {},
                kAddr,
                makeOpaqueAux(OpaqueKind::RDTSC, 0)});
  block.append({Opcode::OPAQUE,
                Value{x86::EDX},
                {},
                kAddr,
                makeOpaqueAux(OpaqueKind::RDTSC, 1)});
  SymbolicExecutor exec;
  REQUIRE(exec.options().useHostTimestamps);
  exec.setRegister(x86::RAX, 0xffffffffffffffffULL);
  exec.setRegister(x86::RDX, 0xffffffffffffffffULL);
  exec.setRegister(x86::CF, 1);
  exec.setRegister(x86::DF, 1);
  const auto result = exec.run(block);
  REQUIRE(result.complete());
  REQUIRE(result.hostTimestamps.size() == 1);
  const auto sample = result.hostTimestamps.front();
  REQUIRE(sample.address == kAddr);
  REQUIRE(sample.kind == OpaqueKind::RDTSC);
  REQUIRE(exec.evaluate(exec.readRegister(x86::RAX)) ==
          (sample.tsc & 0xffffffffULL));
  REQUIRE(exec.evaluate(exec.readRegister(x86::RDX)) == (sample.tsc >> 32));
  REQUIRE(exec.evaluate(exec.readRegister(x86::CF)) == 1);
  REQUIRE(exec.evaluate(exec.readRegister(x86::DF)) == 1);
}

TEST_CASE("SymbolicExecutor - host timestamp groups surviving result ops",
          "[ignil][symbolic][opaque][host-tsc]") {
#if !defined(__x86_64__) && !defined(__i386__) && !defined(_M_X64) &&          \
        !defined(_M_IX86)
  SKIP("native x86 timestamp test requires an x86 host");
#endif
  Block block{kAddr};
  std::vector<unsigned> indices{0, 1};
  std::size_t count = 1;
  SECTION("low result alone") { indices = {0}; }
  SECTION("high result alone") { indices = {1}; }
  SECTION("high first still shares sample") { indices = {1, 0}; }
  SECTION("same PC repeated in one run") {
    indices = {0, 1, 0, 1};
    count = 2;
  }
  SECTION("same PC low-only repeated") {
    indices = {0, 0};
    count = 2;
  }
  SECTION("same PC high-only repeated") {
    indices = {1, 1};
    count = 2;
  }
  for (unsigned index: indices)
    block.append({Opcode::OPAQUE,
                  Value{index == 0 ? x86::EAX : x86::EDX},
                  {},
                  kAddr,
                  makeOpaqueAux(OpaqueKind::RDTSC, index)});
  SymbolicExecutor exec;
  auto result = exec.run(block);
  REQUIRE(result.complete());
  REQUIRE(result.hostTimestamps.size() == count);
  const auto sample = result.hostTimestamps.back();
  if (std::find(indices.begin(), indices.end(), 0) != indices.end())
    REQUIRE(exec.evaluate(exec.readRegister(x86::EAX)) ==
            (sample.tsc & 0xffffffffULL));
  if (std::find(indices.begin(), indices.end(), 1) != indices.end())
    REQUIRE(exec.evaluate(exec.readRegister(x86::EDX)) == (sample.tsc >> 32));
  // A new run (including after restore) is not a cache lookup for this PC.
  auto snapshot = exec.state();
  exec.setState(snapshot);
  REQUIRE(exec.run(block).hostTimestamps.size() == count);
}

TEST_CASE("SymbolicExecutor - explicit timestamp overrides beat native default",
          "[ignil][symbolic][opaque][host-tsc]") {
  SymbolicExecutor exec;
  Block block{kAddr};
  block.append({Opcode::OPAQUE,
                Value{x86::EAX},
                {},
                kAddr,
                makeOpaqueAux(OpaqueKind::RDTSC, 0)});
  block.append({Opcode::OPAQUE,
                Value{x86::EDX},
                {},
                kAddr,
                makeOpaqueAux(OpaqueKind::RDTSC, 1)});
  exec.setConcreteOpaque(OpaqueKind::RDTSC, 0, {0x76543210, 0xfedcba98});
  auto result = exec.run(block);
  REQUIRE(result.complete());
  REQUIRE(result.hostTimestamps.empty());
  REQUIRE(exec.evaluate(exec.readRegister(x86::EAX)) == 0x76543210);
  REQUIRE(exec.evaluate(exec.readRegister(x86::EDX)) == 0xfedcba98);
  // A partial explicit tuple must not mix an override with host high bits.
  exec.setConcreteOpaque(OpaqueKind::RDTSC, 0, {7});
  result = exec.run(block);
  REQUIRE(result.hostTimestamps.empty());
  REQUIRE(exec.evaluate(exec.readRegister(x86::EAX)) == 7);
  REQUIRE_FALSE(exec.evaluate(exec.readRegister(x86::EDX)).has_value());
}

TEST_CASE("SymbolicExecutor - native timestamp mode can be disabled and reset",
          "[ignil][symbolic][opaque][host-tsc]") {
  SymbolicOptions opts;
  opts.useHostTimestamps = false;
  SymbolicExecutor exec{opts};
  Block block{kAddr};
  block.append({Opcode::OPAQUE,
                Value{x86::EAX},
                {},
                kAddr,
                makeOpaqueAux(OpaqueKind::RDTSC, 0)});
  auto result = exec.run(block);
  REQUIRE(result.hostTimestamps.empty());
  REQUIRE_FALSE(exec.evaluate(exec.readRegister(x86::EAX)).has_value());
  exec.reset();
  REQUIRE_FALSE(exec.options().useHostTimestamps);
  exec.setHostTimestamps(true);
  REQUIRE(exec.options().useHostTimestamps);
  exec.setHostTimestamps(false);
  REQUIRE(exec.run(block).hostTimestamps.empty());
}

TEST_CASE("SymbolicExecutor - host RDTSCP results include paired TSC AUX",
          "[ignil][symbolic][opaque][host-tsc]") {
  Block block{kAddr};
  for (unsigned index = 0; index < 3; ++index) {
    const auto reg = index == 0 ? x86::EAX : index == 1 ? x86::EDX : x86::ECX;
    block.append({Opcode::OPAQUE,
                  Value{reg},
                  {},
                  kAddr,
                  makeOpaqueAux(OpaqueKind::RDTSCP, index)});
  }
  SymbolicExecutor exec;
  auto result = exec.run(block);
  REQUIRE(result.ok());
  if (result.hostTimestamps.empty()) {
    REQUIRE_FALSE(result.warnings.empty());
    REQUIRE_FALSE(exec.evaluate(exec.readRegister(x86::EAX)).has_value());
    return; // Older/non-x86 hosts keep unsupported RDTSCP symbolic.
  }
  REQUIRE(result.complete());
  REQUIRE(result.hostTimestamps.size() == 1);
  const auto sample = result.hostTimestamps.front();
  REQUIRE(sample.kind == OpaqueKind::RDTSCP);
  REQUIRE(exec.evaluate(exec.readRegister(x86::EAX)) ==
          (sample.tsc & 0xffffffffULL));
  REQUIRE(exec.evaluate(exec.readRegister(x86::EDX)) == (sample.tsc >> 32));
  REQUIRE(exec.evaluate(exec.readRegister(x86::ECX)) == sample.aux);
}

TEST_CASE("SymbolicExecutor - shared effect memory preserves aliases and overlaps",
          "[symbolic][memory-effects]") {
  SymbolicExecutor exec;
  auto p = exec.symbolizeRegister(x86::RDI, "p");
  auto q = exec.symbolizeRegister(x86::RSI, "q");
  auto x = exec.symbolizeRegister(x86::EAX, "x");
  REQUIRE(exec.state().enableMemoryEffects());
  REQUIRE_FALSE(exec.state().enableMemoryEffects());
  Block block(kAddr);
  block.append({Opcode::STORE, std::nullopt, {Value{x86::RDI}, Value{x86::EAX}}, kAddr});
  block.append({Opcode::STORE, std::nullopt, {Value{x86::RSI}, Value{Const{0x5a, 8}}}, kAddr+1});
  block.append({Opcode::LOAD, Value{x86::EBX}, {Value{x86::RDI}}, kAddr+2});
  auto run = exec.run(block);
  REQUIRE(run.complete());
  REQUIRE(run.unresolved.empty());
  const auto *effects = exec.state().memoryEffects();
  REQUIRE(effects);
  REQUIRE(effects->events().size() == 3);
  REQUIRE(effects->events()[0].isStore);
  REQUIRE_FALSE(effects->events()[2].isStore);
  auto returned = exec.readRegister(x86::EBX);
  auto equal = (x & exec.bv(0xffffff00, 32)) | exec.bv(0x5a, 32);
  auto overlap = (x & exec.bv(0xffff00ff, 32)) | exec.bv(0x5a00, 32);
  REQUIRE(exec.proves(z3::implies(p == q, returned == equal)) == true);
  REQUIRE(exec.proves(z3::implies(q == p+1, returned == overlap)) == true);
  REQUIRE(exec.proves(z3::implies(q == p+4, returned == x)) == true);
}

TEST_CASE("SymbolicExecutor - effect snapshots retain order and get fresh load tokens",
          "[symbolic][memory-effects]") {
  SymbolicExecutor exec;
  exec.symbolizeRegister(x86::RDI, "p");
  exec.state().enableMemoryEffects();
  const auto before = exec.state();
  Block block(kAddr);
  block.append({Opcode::LOAD, Value{x86::EAX}, {Value{x86::RDI}}, kAddr});
  REQUIRE(exec.run(block).complete());
  const auto first = exec.state().memoryEffects()->events()[0].value;
  auto after = exec.state();
  exec.setState(before);
  REQUIRE(exec.state().memoryEffects()->events().empty());
  REQUIRE(exec.run(block).complete());
  const auto second = exec.state().memoryEffects()->events()[0].value;
  REQUIRE_FALSE(z3::eq(first, second));
  REQUIRE(after.memoryEffects()->events().size() == 1);
  REQUIRE_THROWS_AS(after.merge(before, "unsupported"), std::invalid_argument);
  REQUIRE_THROWS_AS(after.diff(before), std::invalid_argument);
  exec.reset();
  REQUIRE_FALSE(exec.state().memoryEffects());
}

TEST_CASE("MemoryEffects - invalid accesses are rejected without events",
          "[symbolic][memory-effects]") {
  z3::context ctx, alien;
  dragon::ignil::MemoryEffects memory(ctx);
  auto p = ctx.bv_const("p", 64);
  REQUIRE_THROWS_AS(memory.load(p, 7, kAddr), std::invalid_argument);
  REQUIRE_THROWS_AS(memory.load(ctx.bv_val(0, 32), 8, kAddr), std::invalid_argument);
  REQUIRE_THROWS_AS(memory.store(p, ctx.bool_val(true), kAddr), std::invalid_argument);
  REQUIRE_THROWS_AS(memory.load(alien.bv_const("q", 64), 8, kAddr), std::invalid_argument);
  REQUIRE(memory.events().empty());
  REQUIRE(z3::eq(memory.initial(), memory.memory()));
}
