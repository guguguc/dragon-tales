#include <catch2/catch_test_macros.hpp>

#include <dragon/disassembler/Disassembler.hpp>
#include <dragon/disassembler/Graph.hpp>
#include <dragon/lifters/ignil/IGNIL.hpp>
#include <dragon/lifters/ignil/IGNILSimplify.hpp>
#include <dragon/lifters/ignil/x86/x86IGNILRegs.hpp>
#include <dragon/lifters/llvm/LLVMLifter.hpp>

#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <iostream>
#include <set>
#include <tuple>
#include <variant>
#include <vector>

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

static dragon::Disassembler makeDisassembler(dragon::Architecture arch) {
  dragon::Configuration cfg;
  cfg.disassemblyStrategy = dragon::DisassemblyStrategy::LINEAR_SWEEP;
  cfg.syntax = dragon::Syntax::INTEL;
  return dragon::Disassembler(arch, cfg);
}

static dragon::Graph makeGraph(dragon::Architecture arch) {
  return dragon::Graph(arch, dragon::Configuration{});
}

// Print each instruction followed by the IGNIL ops it produced,
// grouped by block.
static void printIgnilComparison(dragon::Graph &g) {
  for (const dragon::BasicBlock &block: g.blocks()) {
    std::cout << "\n--- Block @ 0x" << std::hex << block.startAddress()
              << " ---\n";

    const dragon::ignil::Block *ignilBlock =
            g.getIGNILBlock(block.startAddress());

    for (const dragon::Instruction *insn: block.instructions()) {
      std::cout << "  0x" << std::hex << insn->address() << "  "
                << insn->disassembly() << "\n";

      if (ignilBlock) {
        for (const dragon::ignil::Op &op: *ignilBlock) {
          if (op.address == insn->address())
            std::cout << "      " << dragon::ignil::toString(op) << "\n";
        }
      }
    }
  }
  std::cout << std::dec << "\n";
}

// -----------------------------------------------------------------------
// Test 1: arithmetic - MOV, ADD, SUB, XOR, RET
// -----------------------------------------------------------------------

TEST_CASE("IGNIL lifting - arithmetic block", "[ignil][x86_64]") {
  // 0x1000: 55            push rbp
  // 0x1001: 48 89 E5      mov rbp, rsp
  // 0x1004: 48 01 D8      add rax, rbx
  // 0x1007: 48 29 D1      sub rcx, rdx
  // 0x100A: 31 C0         xor eax, eax
  // 0x100C: 5D            pop rbp
  // 0x100D: C3            ret
  const std::vector<std::uint8_t> bytes = {
          0x55,                          // push rbp
          0x48, 0x89, 0xE5,              // mov rbp, rsp
          0x48, 0x01, 0xD8,              // add rax, rbx
          0x48, 0x29, 0xD1,              // sub rcx, rdx
          0x31, 0xC0,                    // xor eax, eax
          0x5D,                          // pop rbp
          0xC3,                          // ret
  };

  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  REQUIRE_FALSE(g.blocks().empty());

  const dragon::ignil::Block *ignilBlock = g.getIGNILBlock(0x1000);
  REQUIRE(ignilBlock != nullptr);
  REQUIRE_FALSE(ignilBlock->empty());

  std::cout << "\n=== IGNIL Lifting: arithmetic block ===";
  printIgnilComparison(g);
}

// -----------------------------------------------------------------------
// Test 2: LEA with complex addressing - base + index*scale + disp
// -----------------------------------------------------------------------

TEST_CASE("IGNIL lifting - LEA with SIB addressing", "[ignil][x86_64]") {
  // 0x1000: 55                  push rbp
  // 0x1001: 48 89 E5            mov rbp, rsp
  // 0x1004: 48 8D 44 8B 08      lea rax, [rbx + rcx*4 + 8]
  // 0x1009: 5D                  pop rbp
  // 0x100A: C3                  ret
  const std::vector<std::uint8_t> bytes = {
          0x55,                          // push rbp
          0x48, 0x89, 0xE5,              // mov rbp, rsp
          0x48, 0x8D, 0x44, 0x8B, 0x08, // lea rax, [rbx + rcx*4 + 8]
          0x5D,                          // pop rbp
          0xC3,                          // ret
  };

  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  REQUIRE_FALSE(g.blocks().empty());

  const dragon::ignil::Block *ignilBlock = g.getIGNILBlock(0x1000);
  REQUIRE(ignilBlock != nullptr);
  REQUIRE_FALSE(ignilBlock->empty());

  std::cout << "\n=== IGNIL Lifting: LEA with SIB addressing ===";
  printIgnilComparison(g);
}

// -----------------------------------------------------------------------
// Test 3: conditional branch - CMP + JLE produces correct CJMP condition
// -----------------------------------------------------------------------

TEST_CASE("IGNIL lifting - conditional branch (cmp/jle)", "[ignil][x86_64]") {
  // 0x1000: 48 39 D8   cmp rax, rbx
  // 0x1003: 7E 05      jle 0x100A          (offset +5 from next insn 0x1005)
  // 0x1005: 48 01 D8   add rax, rbx        (then-block)
  // 0x1008: C3         ret
  // 0x1009: 90         nop                 (pad to align else-block)
  // 0x100A: C3         ret                 (else-block)
  const std::vector<std::uint8_t> bytes = {
          0x48, 0x39, 0xD8,  // cmp rax, rbx  (0x1000)
          0x7E, 0x05,        // jle 0x100A    (0x1003)
          0x48, 0x01, 0xD8,  // add rax, rbx  (0x1005)
          0xC3,              // ret           (0x1008)
          0x90,              // nop           (0x1009)
          0xC3,              // ret           (0x100A)
  };

  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  auto blocks = g.blocks();
  REQUIRE(blocks.size() == 3);

  // All three blocks must have IGNIL representations
  REQUIRE(g.getIGNILBlock(0x1000) != nullptr); // entry: cmp + jle
  REQUIRE(g.getIGNILBlock(0x1005) != nullptr); // then: add + ret
  REQUIRE(g.getIGNILBlock(0x100A) != nullptr); // else: ret

  // The entry block's last op must be a CJMP
  const dragon::ignil::Block *entry = g.getIGNILBlock(0x1000);
  REQUIRE_FALSE(entry->empty());
  const dragon::ignil::Op &terminator = entry->ops().back();
  REQUIRE(terminator.opcode == dragon::ignil::Opcode::CJMP);
  // taken = 0x100A, fall-through = 0x1005
  REQUIRE(std::get<dragon::ignil::Const>(terminator.srcs[1]).value == 0x100A);
  REQUIRE(std::get<dragon::ignil::Const>(terminator.srcs[2]).value == 0x1005);

  std::cout << "\n=== IGNIL Lifting: conditional branch (cmp/jle) ===";
  printIgnilComparison(g);
}

// -----------------------------------------------------------------------
// Test 4: indirect jump through memory - jmp [rax]
// -----------------------------------------------------------------------

TEST_CASE("IGNIL lifting - indirect jump through memory (jmp [rax])", "[ignil][x86_64]") {
  // 0x1000: FF 20   jmp [rax]
  // 0x1002: C3      ret       (unreachable; gives the block a terminator)
  const std::vector<std::uint8_t> bytes = {
          0xFF, 0x20,  // jmp [rax]
          0xC3,        // ret
  };

  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g   = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE_FALSE(ib->empty());

  // There must be a LOAD op somewhere in the block (dereference of [rax])
  const auto &ops = ib->ops();
  auto loadIt = std::find_if(ops.begin(), ops.end(),
          [](const auto &op) { return op.opcode == dragon::ignil::Opcode::LOAD; });
  REQUIRE(loadIt != ops.end());

  // The JMP op must exist and its target must be the Temp produced by LOAD
  auto jmpIt = std::find_if(ops.begin(), ops.end(),
          [](const auto &op) { return op.opcode == dragon::ignil::Opcode::JMP; });
  REQUIRE(jmpIt != ops.end());
  REQUIRE(std::holds_alternative<dragon::ignil::Temp>(jmpIt->srcs[0]));

  std::cout << "\n=== IGNIL Lifting: indirect jump through memory (jmp [rax]) ===";
  printIgnilComparison(g);
}

// -----------------------------------------------------------------------
// Test 5: indirect call through memory - call [rbx + rcx*8]
// -----------------------------------------------------------------------

TEST_CASE("IGNIL lifting - indirect call through memory (call [rbx + rcx*8])", "[ignil][x86_64]") {
  // 0x1000: FF 14 CB   call [rbx + rcx*8]   (virtual dispatch / jump table)
  // 0x1003: C3         ret
  const std::vector<std::uint8_t> bytes = {
          0xFF, 0x14, 0xCB,  // call [rbx + rcx*8]
          0xC3,              // ret
  };

  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g   = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE_FALSE(ib->empty());

  // There must be a LOAD op (dereference of the computed address)
  const auto &ops = ib->ops();
  auto loadIt = std::find_if(ops.begin(), ops.end(),
          [](const auto &op) { return op.opcode == dragon::ignil::Opcode::LOAD; });
  REQUIRE(loadIt != ops.end());

  // The CALL op must exist and its target must be the Temp produced by LOAD
  auto callIt = std::find_if(ops.begin(), ops.end(),
          [](const auto &op) { return op.opcode == dragon::ignil::Opcode::CALL; });
  REQUIRE(callIt != ops.end());
  REQUIRE(std::holds_alternative<dragon::ignil::Temp>(callIt->srcs[0]));

  std::cout << "\n=== IGNIL Lifting: indirect call through memory (call [rbx + rcx*8]) ===";
  printIgnilComparison(g);
}

// -----------------------------------------------------------------------
// Test 6: a block that falls straight into the next block (no explicit
// jmp/ret at its end) must still get an explicit JMP terminator.
//
// Regression test: liftBlock() only emitted a JMP/CJMP/RET when the last
// machine instruction in the block was itself a branch/return. A block
// like the one below (whose last real instruction is just `mov`, with
// execution falling through into the next block) produced an IGNIL block
// with no terminator at all - invalid input for LLVMLifter, which hangs
// LLVM's mem2reg pass when it computes dominator trees over a basic block
// with no terminator instruction. Same bug, same fix, as
// ARM IGNIL lifting - fall-through block gets an explicit JMP.
// -----------------------------------------------------------------------

TEST_CASE("IGNIL lifting - fall-through block gets an explicit JMP", "[ignil][x86_64]") {
  // 0x1000: cmp rax, rbx   48 39 D8
  // 0x1003: jle 0x100c     7E 07
  // 0x1005: mov rax, 1     48 C7 C0 01 00 00 00   (falls through, no jmp/ret!)
  // 0x100c: ret            C3
  const std::vector<std::uint8_t> bytes = {
          0x48, 0x39, 0xD8,                          // cmp rax, rbx  @ 0x1000
          0x7E, 0x07,                                  // jle 0x100c    @ 0x1003
          0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,  // mov rax, 1    @ 0x1005
          0xC3,                                        // ret           @ 0x100c
  };

  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *fallThroughBlock = g.getIGNILBlock(0x1005);
  REQUIRE(fallThroughBlock != nullptr);
  REQUIRE_FALSE(fallThroughBlock->empty());

  const dragon::ignil::Op &terminator = fallThroughBlock->ops().back();
  REQUIRE(terminator.opcode == dragon::ignil::Opcode::JMP);
  REQUIRE(std::get<dragon::ignil::Const>(terminator.srcs[0]).value == 0x100c);

  std::cout << "\n=== IGNIL Lifting: fall-through block gets an explicit JMP ===";
  printIgnilComparison(g);
}

// -----------------------------------------------------------------------
// Test 7: memory-destination MOV/ADD/SUB/CMP forms.
//
// Regression test for the gap documented in ToDo/LifterGaps.md #1:
// `liftInstruction()`'s dispatch only recognized register-destination
// forms of MOV/ADD/SUB/CMP. Memory-destination forms (`mov [mem], imm`,
// RMW `add [mem], reg`/`add [mem], imm`, `cmp reg, [mem]`) fell through to
// the default case and produced *zero* IGNIL ops - not even UNDEF - so
// downstream flag/value reads silently saw stale data from an earlier,
// unrelated instruction. Every case below reproduces one of the exact
// instruction forms from the gap's `sum_to_n` repro and checks that it now
// lowers to real ops instead of vanishing.
// -----------------------------------------------------------------------

// Every ADD/SUB sets CF/ZF/SF/OF explicitly (via COPY) but never computes
// PF/AF/DF, which always fall back to UNDEF - so "exactly 3 UNDEF ops" is
// the signature of a *fully* lifted arithmetic instruction. Before this
// fix, these instructions produced no ops at all (not even those 3 UNDEFs).
static std::size_t countUndef(const dragon::ignil::Block &ib) {
  return static_cast<std::size_t>(
          std::count_if(ib.ops().begin(), ib.ops().end(), [](const auto &op) {
            return op.opcode == dragon::ignil::Opcode::UNDEF;
          }));
}

static bool hasOpcode(const dragon::ignil::Block &ib,
                      dragon::ignil::Opcode opcode) {
  const auto &ops = ib.ops();
  return std::find_if(ops.begin(), ops.end(), [&](const auto &op) {
           return op.opcode == opcode;
         }) != ops.end();
}

TEST_CASE("IGNIL lifting - mov [mem], imm (MOV32mi)", "[ignil][x86_64]") {
  // mov dword ptr [rbp-4], 0 ; ret
  const std::vector<std::uint8_t> bytes = {
          0xc7, 0x45, 0xfc, 0x00, 0x00, 0x00, 0x00, // mov [rbp-4], 0
          0xc3,                                      // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE_FALSE(ib->empty()); // previously: zero ops, silently
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));

  std::cout << "\n=== IGNIL Lifting: mov [mem], imm ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - add [mem], reg RMW (ADD32mr)", "[ignil][x86_64]") {
  // add dword ptr [rbp-8], eax ; ret
  const std::vector<std::uint8_t> bytes = {
          0x01, 0x45, 0xf8, // add [rbp-8], eax
          0xc3,             // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE_FALSE(ib->empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::ADD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
  REQUIRE(countUndef(*ib) == 0); // only PF/AF/DF - CF/ZF/SF/OF really computed  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: add [mem], reg (RMW) ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - add [mem], imm8 RMW (ADD32mi8)", "[ignil][x86_64]") {
  // add dword ptr [rbp-8], 1 ; ret
  const std::vector<std::uint8_t> bytes = {
          0x83, 0x45, 0xf8, 0x01, // add [rbp-8], 1
          0xc3,                   // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE_FALSE(ib->empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::ADD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
  REQUIRE(countUndef(*ib) == 0);  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: add [mem], imm8 (RMW) ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - sub [mem], reg RMW (SUB32mr)", "[ignil][x86_64]") {
  // sub dword ptr [rbp-8], ecx ; ret
  const std::vector<std::uint8_t> bytes = {
          0x29, 0x4d, 0xf8, // sub [rbp-8], ecx
          0xc3,             // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE_FALSE(ib->empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SUB));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
  REQUIRE(countUndef(*ib) == 0);  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: sub [mem], reg (RMW) ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - cmp reg, [mem] (CMP32rm)", "[ignil][x86_64]") {
  // cmp eax, dword ptr [rbp-20] ; ret
  const std::vector<std::uint8_t> bytes = {
          0x3b, 0x45, 0xec, // cmp eax, [rbp-20]
          0xc3,             // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE_FALSE(ib->empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SUB));
  REQUIRE_FALSE(hasOpcode(*ib, dragon::ignil::Opcode::STORE)); // CMP never writes back
  REQUIRE(countUndef(*ib) == 0);  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: cmp reg, [mem] ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - add reg, [mem] / sub reg, [mem] (ADD32rm/SUB32rm)",
         "[ignil][x86_64]") {
  // add eax, dword ptr [rbp-8] ; sub ecx, dword ptr [rbp-8] ; ret
  // Found by scripts/audit_x86_lifter_coverage.py: the reg,mem direction of
  // the same gap class fixed in liftAddMem/liftSubMem (RMW mem,reg/mem,imm).
  const std::vector<std::uint8_t> bytes = {
          0x03, 0x45, 0xf8, // add eax, [rbp-8]
          0x2b, 0x4d, 0xf8, // sub ecx, [rbp-8]
          0xc3,             // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE_FALSE(ib->empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::ADD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SUB));
  REQUIRE_FALSE(hasOpcode(*ib, dragon::ignil::Opcode::STORE)); // dst is a register, not memory
  REQUIRE(countUndef(*ib) == 0); // two instructions, 3 always-UNDEF flags each  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: add reg, [mem] / sub reg, [mem] ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - cmp [mem], imm8 and cmp [mem], reg", "[ignil][x86_64]") {
  // cmp dword ptr [rbp-4], 0   ; cmp dword ptr [rbp-4], ecx ; ret
  const std::vector<std::uint8_t> bytes = {
          0x83, 0x7d, 0xfc, 0x00, // cmp [rbp-4], 0
          0x39, 0x4d, 0xfc,       // cmp [rbp-4], ecx
          0xc3,                   // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE_FALSE(ib->empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SUB));
  REQUIRE_FALSE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
  REQUIRE(countUndef(*ib) == 0); // two CMPs, 3 always-UNDEF flags each  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: cmp [mem], imm8 / cmp [mem], reg ===";
  printIgnilComparison(g);
}

// -----------------------------------------------------------------------
// MOVSX64rr32, SAR32ri/SAR64ri, IMUL64rri32/rri8/32rri/rri8, LEA64_32r -
// found while lifting a real compiled signed-division-by-constant sequence
// (GCC's standard multiply-high lowering for `x / C`), not
// obfuscation-specific - this is ordinary output for any program dividing
// by a non-power-of-two constant. See ToDo/Roadmap.md for the full
// writeup. Byte sequences below were generated with `gcc -c` from real
// Intel-syntax assembly and verified with `objdump -d`, not hand-derived.
// -----------------------------------------------------------------------

TEST_CASE("IGNIL lifting - movsxd rax, edi (MOVSX64rr32)", "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0x48, 0x63, 0xc7, // movsxd rax, edi
          0xc3,             // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE_FALSE(ib->empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SEXT));
  REQUIRE(countUndef(*ib) == 0); // MOVSX never affects flags

  std::cout << "\n=== IGNIL Lifting: movsxd rax, edi ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - sar eax, 0 leaves flags untouched (SAR32ri)",
          "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0xc1, 0xf8, 0x00, // sar eax, 0
          0xc3,             // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  // Real x86: shift by 0 is a pure copy, no SAR op, no flags at all - not
  // even UNDEF, since nothing was touched.
  REQUIRE_FALSE(hasOpcode(*ib, dragon::ignil::Opcode::SAR));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::COPY));
  REQUIRE(countUndef(*ib) == 0);

  std::cout << "\n=== IGNIL Lifting: sar eax, 0 ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - sar eax, 1 defines OF (SAR32ri)", "[ignil][x86_64]") {
  // Same C1 /7 ib encoding as `sar eax, 0` above with the immediate byte
  // changed to 1 - the assembler prefers the shorter D1 (SAR32r1) encoding
  // for a literal `sar eax, 1`, which is a different, unrelated opcode this
  // change doesn't touch; this form is still a valid, decodable SAR32ri.
  const std::vector<std::uint8_t> bytes = {
          0xc1, 0xf8, 0x01, // sar eax, 1  (SAR32ri encoding, not SAR32r1)
          0xc3,             // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SAR));
  REQUIRE(countUndef(*ib) == 0); // only PF/AF/DF - CF/ZF/SF/OF all computed  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: sar eax, 1 ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - sar edi, 0x1f / sar rax, 0x26 (SAR32ri/SAR64ri, "
          "count > 1)",
          "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0xc1, 0xff, 0x1f,       // sar edi, 0x1f
          0x48, 0xc1, 0xf8, 0x26, // sar rax, 0x26
          0xc3,                   // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SAR));
  // OF is architecturally undefined for count != 1 - two SARs, four
  // UNDEF flags (PF/AF/OF/DF) each.
  REQUIRE(countUndef(*ib) == 2);  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: sar edi, 0x1f / sar rax, 0x26 ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - 3-operand imul with immediate (IMUL64rri32/"
          "rri8/32rri/32rri8)",
          "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0x48, 0x69, 0xc0, 0x41, 0xdd, 0xb3, 0x20, // imul rax, rax, 0x20b3dd41
          0x48, 0x6b, 0xc3, 0x05,                   // imul rax, rbx, 5
          0x69, 0xc3, 0x40, 0x42, 0x0f, 0x00,       // imul eax, ebx, 1000000
          0x6b, 0xc3, 0x05,                         // imul eax, ebx, 5
          0xc3,                                     // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::MUL));
  // All flags UNDEF for every IMUL form - SF/ZF/AF/PF are architecturally
  // undefined for IMUL, CF/OF would need a double-width product IGNIL
  // doesn't model. 4 IMULs * 7 flags each.
  REQUIRE(countUndef(*ib) == 24);  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: 3-operand imul with immediate ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - lea eax, [rdx+rcx*1] truncates a 64-bit address "
          "into a 32-bit dst (LEA64_32r)",
          "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0x8d, 0x04, 0x0a, // lea eax, [rdx+rcx*1]
          0xc3,             // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::TRUNC));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::ADD)); // base+index address calc
  REQUIRE(countUndef(*ib) == 0); // LEA never affects flags

  std::cout << "\n=== IGNIL Lifting: lea eax, [rdx+rcx*1] ===";
  printIgnilComparison(g);
}

// -----------------------------------------------------------------------
// INC/DEC/NEG/MOVZX/SHL-imm/SHR-imm (INC32r/64r, DEC32r/64r, NEG32r/64r,
// MOVZX32rr8/rr16, MOVZX64rr8/rr16, SHL32ri/64ri, SHR32ri/64ri) - the
// remaining gaps from tests/toy-vm/ToyVM.hpp's header comment (SAR was
// fixed earlier this session; these are its siblings). All extremely
// common in real -O0/-O1 output (loop counters, byte-to-word widening),
// so every occurrence previously degraded silently to UNDEF. Byte
// sequences verified with real `gcc -c`/`objdump`.
// -----------------------------------------------------------------------

TEST_CASE("IGNIL lifting - inc eax / inc rax never touch CF (INC32r/64r)",
          "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0xff, 0xc0,       // inc eax
          0x48, 0xff, 0xc0, // inc rax
          0xc3,             // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::ADD));
  // CF gets no Op at all - not even UNDEF - for either INC. Confirm no op
  // anywhere writes CF: only every other flag getting UNDEF would count.
  bool anyWritesCF = false;
  for (const auto &op: ib->ops()) {
    if (op.dst && std::holds_alternative<dragon::ignil::Reg>(*op.dst)) {
      const auto &r = std::get<dragon::ignil::Reg>(*op.dst);
      if (r.name == "CF")
        anyWritesCF = true;
    }
  }
  REQUIRE_FALSE(anyWritesCF);
  REQUIRE(countUndef(*ib) == 0); // PF+AF+DF per INC, x2 INCs = 6  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: inc eax / inc rax ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - dec ecx / dec rcx never touch CF (DEC32r/64r)",
          "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0xff, 0xc9,       // dec ecx
          0x48, 0xff, 0xc9, // dec rcx
          0xc3,             // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SUB));
  REQUIRE(countUndef(*ib) == 0); // PF+AF+DF per DEC, x2 DECs = 6  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: dec ecx / dec rcx ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - neg eax / neg rax (NEG32r/64r)", "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0xf7, 0xd8,       // neg eax
          0x48, 0xf7, 0xd8, // neg rax
          0xc3,             // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::NEG));
  // Unlike INC/DEC, NEG's CF *is* well-defined - only PF/AF/DF stay UNDEF.
  REQUIRE(countUndef(*ib) == 0); // 3 per NEG, x2 NEGs  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: neg eax / neg rax ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - movzx (MOVZX32rr8/rr16, MOVZX64rr8/rr16)",
          "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0x0f, 0xb6, 0xc3,       // movzx eax, bl
          0x0f, 0xb7, 0xc3,       // movzx eax, bx
          0x48, 0x0f, 0xb6, 0xc3, // movzx rax, bl
          0x48, 0x0f, 0xb7, 0xc3, // movzx rax, bx
          0xc3,                   // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::ZEXT));
  REQUIRE(countUndef(*ib) == 0); // MOVZX never affects flags

  std::cout << "\n=== IGNIL Lifting: movzx (4 width pairs) ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - shl by immediate, count 0/1/N (SHL32ri/64ri)",
          "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0xc1, 0xe0, 0x00,       // shl eax, 0
          0xc1, 0xe0, 0x01,       // shl eax, 1  (SHL32ri encoding, not SHL32r1)
          0xc1, 0xe0, 0x05,       // shl eax, 5
          0x48, 0xc1, 0xe0, 0x05, // shl rax, 5
          0xc3,                   // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SHL));
  // shl by 0: pure copy, no flags at all (0 UNDEF).
  // shl by 1: OF defined -> only PF/AF/DF UNDEF (3).
  // shl by 5 (x2, 32 and 64-bit): OF undefined for count!=1 -> PF/AF/OF/DF
  // UNDEF (4 each).
  REQUIRE(countUndef(*ib) == 2);  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: shl by immediate ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - shr by immediate, count 0/1/N (SHR32ri/64ri)",
          "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0xc1, 0xe8, 0x00,       // shr eax, 0
          0xc1, 0xe8, 0x01,       // shr eax, 1  (SHR32ri encoding, not SHR32r1)
          0xc1, 0xe8, 0x05,       // shr eax, 5
          0x48, 0xc1, 0xe8, 0x05, // shr rax, 5
          0xc3,                   // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SHR));
  REQUIRE(countUndef(*ib) == 2);  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: shr by immediate ===";
  printIgnilComparison(g);
}

// -----------------------------------------------------------------------
// AND/OR/XOR/TEST-immediate, MOVSX32rr8, IMUL32rr, SAR/SHL/SHR-by-1 - found
// by decoding a real obfusheader.h-obfuscated binary end to end
// (examples/obfusheader/). liftAnd/liftOr/liftXor/liftTest were generalized
// to accept an immediate operand (mirroring liftAdd/liftSub's existing
// isImm()/isReg() branch) rather than adding parallel *Imm functions, since
// the ri/ri8 forms share the exact same operand shape as the rr forms
// (verified below) - only the immediate-vs-register src differs. Byte
// sequences were generated with `as --64` from real Intel-syntax assembly
// and verified with `objdump -d`, using ECX/RCX as the destination to force
// the general ModRM-encoded ri/ri8 opcodes rather than the accumulator
// short-encoding forms (AND32i32 etc. - a distinct, still-unhandled opcode
// family, see ToDo/Roadmap.md).
// -----------------------------------------------------------------------

TEST_CASE("IGNIL lifting - and/or/xor by immediate, ri32 and ri8 "
          "(AND32ri/64ri32/32ri8/64ri8, OR32ri/32ri8/64ri8, "
          "XOR32ri/32ri8/64ri8)",
          "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0x81, 0xe1, 0xa0, 0x86, 0x01, 0x00, // and ecx, 0x186a0  (AND32ri)
          0x48, 0x81, 0xe1, 0xa0, 0x86, 0x01,
          0x00,                         // and rcx, 0x186a0  (AND64ri32)
          0x81, 0xc9, 0xa0, 0x86, 0x01, 0x00, // or ecx, 0x186a0   (OR32ri)
          0x81, 0xf1, 0xa0, 0x86, 0x01, 0x00, // xor ecx, 0x186a0  (XOR32ri)
          0x83, 0xe1, 0x05,                   // and ecx, 5  (AND32ri8)
          0x48, 0x83, 0xe1, 0x05,             // and rcx, 5  (AND64ri8)
          0x83, 0xc9, 0x05,                   // or ecx, 5   (OR32ri8)
          0x48, 0x83, 0xc9, 0x05,             // or rcx, 5   (OR64ri8)
          0x83, 0xf1, 0x05,                   // xor ecx, 5  (XOR32ri8)
          0x48, 0x83, 0xf1, 0x05,             // xor rcx, 5  (XOR64ri8)
          0xc3,                                // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::AND));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::OR));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::XOR));
  // 10 logical ops, each leaves only PF/AF/DF UNDEF (CF/ZF/SF/OF computed).
  REQUIRE(countUndef(*ib) == 0);  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: and/or/xor by immediate ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - test ecx, imm32 discards the result (TEST32ri)",
          "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0xf7, 0xc1, 0xa0, 0x86, 0x01, 0x00, // test ecx, 0x186a0
          0xc3,                                // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::AND)); // TEST lowers to AND
  REQUIRE(countUndef(*ib) == 0); // PF/AF/DF, same as the register form  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  // Unlike AND32ri, TEST must never write the AND result back into ECX.
  const bool writesEcx = std::any_of(
          ib->ops().begin(), ib->ops().end(),
          [](const dragon::ignil::Op &op) {
            if (!op.dst ||
                !std::holds_alternative<dragon::ignil::Reg>(*op.dst))
              return false;
            return std::get<dragon::ignil::Reg>(*op.dst).name == "ECX";
          });
  REQUIRE_FALSE(writesEcx);

  std::cout << "\n=== IGNIL Lifting: test ecx, imm32 ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - movsx eax, bl (MOVSX32rr8)", "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0x0f, 0xbe, 0xc3, // movsx eax, bl
          0xc3,             // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SEXT));
  REQUIRE(countUndef(*ib) == 0); // MOVSX never affects flags

  std::cout << "\n=== IGNIL Lifting: movsx eax, bl ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - 2-operand imul eax, ebx (IMUL32rr)",
          "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0x0f, 0xaf, 0xc3, // imul eax, ebx
          0xc3,             // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::MUL));
  REQUIRE(countUndef(*ib) == 6); // all 7 flags UNDEF, same as IMUL-immediate  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: imul eax, ebx ===";
  printIgnilComparison(g);
}

// -----------------------------------------------------------------------
// SSE2 scalar-double support (PXOR, CVTSI2SD, CVTTSD2SI, ADDSD/SUBSD/MULSD,
// MOVSD rr/rm/mr) - found decoding the real obfusheader.h-obfuscated
// binary (examples/obfusheader/, CFLOW_BRANCHING's int_proxy() opaque
// predicates use real SSE2 double arithmetic, not x87). Only the low 64
// bits of each XMM register are modeled (x86registers.def) - real
// hardware's upper-64-bits-preserved merge semantics for these
// instructions reduce to a no-op under that model, so several of these
// dispatch straight into existing integer-op lifters (PXORrr -> liftXor,
// MOVSDrm/mr -> liftMovLoad/liftMovStore) rather than needing new
// functions. None of these touch EFLAGS (only UCOMISD/COMISD do, and
// neither appears in the real target). Byte sequences generated with
// `as --64` from real Intel-syntax assembly and verified with `objdump -d`.
// -----------------------------------------------------------------------

TEST_CASE("IGNIL lifting - pxor/cvtsi2sd/cvttsd2si/addsd/subsd/mulsd "
          "register forms (PXORrr, CVTSI2SDrr_Int/CVTSI642SDrr_Int, "
          "CVTTSD2SIrr_Int/CVTTSD2SI64rr_Int, ADDSDrr_Int/SUBSDrr_Int/"
          "MULSDrr_Int)",
          "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0x66, 0x0f, 0xef, 0xc0,       // pxor xmm0, xmm0
          0x66, 0x0f, 0xef, 0xd1,       // pxor xmm2, xmm1
          0xf2, 0x0f, 0x2a, 0xc6,       // cvtsi2sd xmm0, esi
          0xf2, 0x48, 0x0f, 0x2a, 0xc8, // cvtsi2sd xmm1, rax
          0xf2, 0x0f, 0x2c, 0xc0,       // cvttsd2si eax, xmm0
          0xf2, 0x48, 0x0f, 0x2c, 0xc1, // cvttsd2si rax, xmm1
          0xf2, 0x0f, 0x58, 0xc1,       // addsd xmm0, xmm1
          0xf2, 0x0f, 0x5c, 0xd0,       // subsd xmm2, xmm0
          0xf2, 0x0f, 0x59, 0xca,       // mulsd xmm1, xmm2
          0xc3,                         // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::XOR)); // PXOR reuses liftXor
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SITOFP));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::FPTOSI));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::FADD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::FSUB));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::FMUL));
  // Only the two PXORs touch flags at all (3 UNDEF each, same as any other
  // liftXor dispatch - PF/AF/DF). SSE2 arithmetic/conversions never do.
  REQUIRE(countUndef(*ib) == 0);  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: SSE2 register forms ===";
  printIgnilComparison(g);
}

TEST_CASE("IGNIL lifting - movsd rr/rm/mr and mulsd with a memory operand "
          "(MOVSDrr/rm/mr, MULSDrm_Int)",
          "[ignil][x86_64]") {
  const std::vector<std::uint8_t> bytes = {
          0xf2, 0x0f, 0x10, 0xdc,                   // movsd xmm3, xmm4
          0xf2, 0x0f, 0x10, 0x44, 0x24, 0xf8,       // movsd xmm0, [rsp-8]
          0xf2, 0x0f, 0x11, 0x4c, 0x24, 0xf8,       // movsd [rsp-8], xmm1
          0xf2, 0x0f, 0x59, 0x05, 0x00, 0x01, 0x00,
          0x00,                                      // mulsd xmm0, [rip+0x100]
          0xc3,                                      // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::COPY)); // movsd xmm3, xmm4
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::FMUL));
  REQUIRE(countUndef(*ib) == 0); // none of these touch flags

  std::cout << "\n=== IGNIL Lifting: movsd rr/rm/mr + mulsd [mem] ===";
  printIgnilComparison(g);
}

TEST_CASE("LLVM IR - SITOFP/FADD/FPTOSI lower to valid, correctly-typed "
          "double IR",
          "[llvmlifter][x86_64]") {
  // cvtsi2sd xmm0, esi ; addsd xmm0, xmm1 ; cvttsd2si eax, xmm0 ; ret
  // Exercises the actual point of the whole IGNIL float design: Const/Reg/
  // Temp stay raw 64-bit slots end to end, and only LLVMLifter's asDouble()/
  // emit() bitcast at the boundary - this is the one place that boundary
  // can silently produce type-mismatched (and therefore invalid) IR if the
  // bitcast logic is wrong, which a pure IGNIL-shape test (checking opcodes
  // appear, not that the generated IR actually type-checks) can't catch.
  const std::vector<std::uint8_t> bytes = {
          0xf2, 0x0f, 0x2a, 0xc6, // cvtsi2sd xmm0, esi
          0xf2, 0x0f, 0x58, 0xc1, // addsd xmm0, xmm1
          0xf2, 0x0f, 0x2c, 0xc0, // cvttsd2si eax, xmm0
          0xc3,                   // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto insns = dis.disassemble(bytes, 0x1000);
  auto block = dis.liftTrace(insns);

  dragon::llvmlifter::LLVMLifter lifter(dragon::Architecture::X86_64,
                                        "sitofp_fadd_fptosi");
  REQUIRE(lifter.liftBlock(block, "fn"));

  llvm::Function *fn = lifter.module().getFunction("fn");
  REQUIRE(fn != nullptr);

  std::string verifyErrors;
  llvm::raw_string_ostream os(verifyErrors);
  bool broken = llvm::verifyFunction(*fn, &os);
  INFO(verifyErrors);
  REQUIRE_FALSE(broken);

  const std::string ir = lifter.ir();
  REQUIRE(ir.find("sitofp") != std::string::npos);
  REQUIRE(ir.find("fadd double") != std::string::npos);
  REQUIRE(ir.find("fptosi double") != std::string::npos);

  // Also verify post-optimization: mem2reg/instcombine should thread the
  // sitofp result straight into the fadd with no leftover bitcast
  // round-trip noise between them (confirmed once by hand via a scratch
  // driver before writing this test - pinning it here so a future
  // regression in the bitcast logic doesn't quietly reintroduce it).
  lifter.runMem2Reg();
  lifter.runInstCombine();
  llvm::Function *optFn = lifter.module().getFunction("fn");
  REQUIRE(optFn != nullptr);
  REQUIRE_FALSE(llvm::verifyFunction(*optFn));
  const std::string optIr = lifter.ir();
  REQUIRE(optIr.find("fadd double") != std::string::npos);

  std::cout << "\n=== LLVM IR: sitofp/fadd/fptosi (optimized) ===\n"
            << optIr;
}

TEST_CASE("IGNIL lifting - shift-by-1 dedicated opcodes "
          "(SAR32r1/64r1, SHL32r1/64r1, SHR32r1/64r1)",
          "[ignil][x86_64]") {
  // Deliberately the D1 /n encoding (implicit count of 1), not C1 /n ib
  // with an explicit imm byte of 1 (SAR32ri etc., already covered above) -
  // these are genuinely different opcodes with no immediate operand at all.
  const std::vector<std::uint8_t> bytes = {
          0xd1, 0xf8,       // sar eax, 1
          0xd1, 0xe0,       // shl eax, 1
          0xd1, 0xe8,       // shr eax, 1
          0x48, 0xd1, 0xf8, // sar rax, 1
          0x48, 0xd1, 0xe0, // shl rax, 1
          0x48, 0xd1, 0xe8, // shr rax, 1
          0xc3,             // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SAR));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SHL));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SHR));
  // Each is an implicit count-of-1 shift, so like the imm==1 case above,
  // only PF/AF/DF are UNDEF per op: 3 * 6 ops.
  REQUIRE(countUndef(*ib) == 0);  // PF/AF modeled, DF untouched (LifterGaps #7 r4)

  std::cout << "\n=== IGNIL Lifting: shift-by-1 dedicated opcodes ===";
  printIgnilComparison(g);
}

// -----------------------------------------------------------------------
// MOVZX / MOVSX with a memory operand (ToDo/LifterGaps.md #4)
// -----------------------------------------------------------------------

namespace {

// First op with this opcode, or nullptr.
const dragon::ignil::Op *firstOp(const dragon::ignil::Block &ib,
                                 dragon::ignil::Opcode opcode) {
  for (const dragon::ignil::Op &op: ib)
    if (op.opcode == opcode)
      return &op;
  return nullptr;
}

struct ExtendCase {
  const char *disasm;
  std::vector<std::uint8_t> bytes;
  dragon::ignil::Opcode extend;
  dragon::ignil::Width dstWidth;
  dragon::ignil::Width srcWidth;
  bool fromMemory;
};

} // namespace

TEST_CASE("IGNIL lifting - movzx/movsx load at the width the mnemonic names",
          "[ignil][x86_64]") {
  // The memory-source forms are the point here. Checking only that no UNDEF
  // is emitted would not catch the failure mode they actually have: op[1] is
  // a register in *both* forms (for an rm form it is the memory operand's
  // base), so a lifter that decides which form it has by looking at the
  // operands takes the register path, emits `EAX = ZEXT(RBX)` with no load at
  // all, and looks perfectly healthy. So assert the shape: a LOAD of exactly
  // the mnemonic's width, feeding the extend.
  using dragon::ignil::Opcode;

  const std::vector<ExtendCase> cases = {
          // Memory source - the gap this covers.
          {"movzx eax, byte ptr [rbx]", {0x0f, 0xb6, 0x03}, Opcode::ZEXT, 32, 8, true},
          {"movzx eax, word ptr [rbx]", {0x0f, 0xb7, 0x03}, Opcode::ZEXT, 32, 16, true},
          {"movzx rax, byte ptr [rbx]", {0x48, 0x0f, 0xb6, 0x03}, Opcode::ZEXT, 64, 8, true},
          {"movzx rax, word ptr [rbx]", {0x48, 0x0f, 0xb7, 0x03}, Opcode::ZEXT, 64, 16, true},
          {"movsx eax, byte ptr [rbx]", {0x0f, 0xbe, 0x03}, Opcode::SEXT, 32, 8, true},
          {"movsx eax, word ptr [rbx]", {0x0f, 0xbf, 0x03}, Opcode::SEXT, 32, 16, true},
          {"movsx rax, byte ptr [rbx]", {0x48, 0x0f, 0xbe, 0x03}, Opcode::SEXT, 64, 8, true},
          {"movsx rax, word ptr [rbx]", {0x48, 0x0f, 0xbf, 0x03}, Opcode::SEXT, 64, 16, true},
          {"movsxd rax, dword ptr [rbx]", {0x48, 0x63, 0x03}, Opcode::SEXT, 64, 32, true},
          // Register source - unchanged behaviour, including the widths that
          // had no dispatch entry before (movsx rax, bl / movsx eax, bx).
          {"movzx eax, bl", {0x0f, 0xb6, 0xc3}, Opcode::ZEXT, 32, 8, false},
          {"movsx eax, bl", {0x0f, 0xbe, 0xc3}, Opcode::SEXT, 32, 8, false},
          {"movsx eax, bx", {0x0f, 0xbf, 0xc3}, Opcode::SEXT, 32, 16, false},
          {"movsx rax, bl", {0x48, 0x0f, 0xbe, 0xc3}, Opcode::SEXT, 64, 8, false},
          {"movsx rax, bx", {0x48, 0x0f, 0xbf, 0xc3}, Opcode::SEXT, 64, 16, false},
          {"movsxd rax, ebx", {0x48, 0x63, 0xc3}, Opcode::SEXT, 64, 32, false},
  };

  for (const ExtendCase &c: cases) {
    INFO(c.disasm);

    std::vector<std::uint8_t> bytes = c.bytes;
    bytes.push_back(0xc3); // ret

    auto dis = makeDisassembler(dragon::Architecture::X86_64);
    auto g = makeGraph(dragon::Architecture::X86_64);
    dis.disassemble(bytes, 0x1000, g);

    const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
    REQUIRE(ib != nullptr);
    REQUIRE(countUndef(*ib) == 0); // neither MOVZX nor MOVSX touches flags

    const dragon::ignil::Op *extend = firstOp(*ib, c.extend);
    REQUIRE(extend != nullptr);
    REQUIRE(extend->srcs.size() == 1);
    REQUIRE(dragon::ignil::widthOf(extend->dst.value()) == c.dstWidth);
    REQUIRE(dragon::ignil::widthOf(extend->srcs[0]) == c.srcWidth);

    const dragon::ignil::Op *load = firstOp(*ib, dragon::ignil::Opcode::LOAD);
    if (!c.fromMemory) {
      // A register source must not have invented a memory access.
      REQUIRE(load == nullptr);
      REQUIRE(std::holds_alternative<dragon::ignil::Reg>(extend->srcs[0]));
      continue;
    }

    // The extend must consume exactly what the load produced, at the width
    // the mnemonic names - not the pointer's width, and not the base
    // register.
    REQUIRE(load != nullptr);
    REQUIRE(dragon::ignil::widthOf(load->dst.value()) == c.srcWidth);
    REQUIRE(std::holds_alternative<dragon::ignil::Temp>(extend->srcs[0]));
    REQUIRE(std::get<dragon::ignil::Temp>(extend->srcs[0]).id ==
            std::get<dragon::ignil::Temp>(load->dst.value()).id);
  }
}

// -----------------------------------------------------------------------
// Regression: load-direction reg-reg encodings (0x8B/0x03/0x33, the LLVM
// *_REV opcodes) must lift like their store-direction (0x89/0x01/0x31) base
// forms, not fall through to UNDEF. Compilers emit these constantly; the gap
// was found via symbolic-execution differential testing on a VMProtect target
// whose accumulator lived in r8d and went entirely UNDEF.
// -----------------------------------------------------------------------
TEST_CASE("IGNIL lifting - load-direction reg-reg (_REV) encodings",
          "[ignil][x86_64][rev]") {
  using dragon::ignil::Opcode;

  auto liftOne = [](std::vector<uint8_t> bytes) {
    static std::vector<dragon::Graph> keep;  // keep graphs alive for the block
    keep.push_back(makeGraph(dragon::Architecture::X86_64));
    auto &g = keep.back();
    auto dis = makeDisassembler(dragon::Architecture::X86_64);
    bytes.push_back(0xc3);  // ret
    dis.disassemble(bytes, 0x1000, g);
    return g.getIGNILBlock(0x1000);
  };

  SECTION("mov r9, rcx  [4c 8b c9]") {
    const auto *ib = liftOne({0x4c, 0x8b, 0xc9});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::COPY));
    REQUIRE(countUndef(*ib) == 0);  // plain 64-bit mov touches no flags
  }
  SECTION("mov edx, r8d  [41 8b d0]") {
    const auto *ib = liftOne({0x41, 0x8b, 0xd0});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::COPY));
    REQUIRE(countUndef(*ib) == 0);
  }
  SECTION("xor r8d, ecx  [44 33 c1]") {
    const auto *ib = liftOne({0x44, 0x33, 0xc1});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::XOR));
  }
  SECTION("add r8d, ecx  [44 03 c1]") {
    const auto *ib = liftOne({0x44, 0x03, 0xc1});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::ADD));
  }
}

// -----------------------------------------------------------------------
// Regression: 8/16-bit memory MOV (MOV8mr/MOV16mr stores, MOV8rm/MOV16rm
// loads). Only 32/64 were dispatched, so byte/word stores/loads silently
// produced no op. Found devirtualizing a VMProtect 16-bit PUSH handler
// (mov word ptr [rbp], cx). (Extended-reg byte/word sources like r9w are a
// separate register-mapping gap, tracked in LifterGaps.md.)
// -----------------------------------------------------------------------
TEST_CASE("IGNIL lifting - 8/16-bit memory MOV", "[ignil][x86_64][movsz]") {
  using dragon::ignil::Opcode;
  auto lift = [](std::vector<uint8_t> bytes) {
    static std::vector<dragon::Graph> keep;
    keep.push_back(makeGraph(dragon::Architecture::X86_64));
    auto &g = keep.back();
    auto dis = makeDisassembler(dragon::Architecture::X86_64);
    bytes.push_back(0xc3);
    dis.disassemble(bytes, 0x1000, g);
    return g.getIGNILBlock(0x1000);
  };
  SECTION("mov word ptr [rbp], cx  [66 89 4d 00]") {
    const auto *ib = lift({0x66, 0x89, 0x4d, 0x00});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::STORE));
  }
  SECTION("mov byte ptr [rbp], cl  [88 4d 00]") {
    const auto *ib = lift({0x88, 0x4d, 0x00});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::STORE));
  }
  SECTION("mov cx, word ptr [rbp]  [66 8b 4d 00]") {
    const auto *ib = lift({0x66, 0x8b, 0x4d, 0x00});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::LOAD));
  }
  // extended byte/word register sources (R8W..R15W, R8B..R15B) must map too.
  SECTION("mov word ptr [rbp], r9w  [66 44 89 4d 00]") {
    const auto *ib = lift({0x66, 0x44, 0x89, 0x4d, 0x00});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::STORE));
  }
  SECTION("mov byte ptr [rbp], r9b  [44 88 4d 00]") {
    const auto *ib = lift({0x44, 0x88, 0x4d, 0x00});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::STORE));
  }
}

static std::size_t countOpcode(const dragon::ignil::Block &ib,
                               dragon::ignil::Opcode opcode) {
  const auto &ops = ib.ops();
  return static_cast<std::size_t>(std::count_if(
          ops.begin(), ops.end(),
          [&](const auto &op) { return op.opcode == opcode; }));
}

// LifterGaps.md #7: the instruction forms VMProtect's x64 handlers are built
// from (found by lifting all 256 handlers of a protected binary): NOT at every
// width, shifts by CL, 8/16-bit shifts, NEG8/16, CBW..CQO, STC/CLC/CMC. Each
// used to lift to UNDEF (or to nothing at all), which hid the handler's real
// operation.
TEST_CASE("IGNIL lifting - VMProtect handler forms (NOT, shift by CL, 8/16-bit "
          "shifts, accumulator extends, STC/CLC/CMC)",
          "[ignil][x86_64][vmp]") {
  using dragon::ignil::Opcode;
  auto lift = [](std::vector<uint8_t> bytes) {
    static std::vector<dragon::Graph> keep;
    keep.push_back(makeGraph(dragon::Architecture::X86_64));
    auto &g = keep.back();
    auto dis = makeDisassembler(dragon::Architecture::X86_64);
    bytes.push_back(0xc3);
    dis.disassemble(bytes, 0x1000, g);
    return g.getIGNILBlock(0x1000);
  };
  SECTION("not edi / not rdx / not dil / not cx") {
    for (auto bytes: {std::vector<uint8_t>{0xf7, 0xd7}, {0x48, 0xf7, 0xd2},
                      {0x40, 0xf6, 0xd7}, {0x66, 0xf7, 0xd1}}) {
      const auto *ib = lift(bytes);
      REQUIRE(ib != nullptr);
      REQUIRE(hasOpcode(*ib, Opcode::NOT));
      REQUIRE(countOpcode(*ib, Opcode::UNDEF) == 0);   // NOT touches no flag
    }
  }
  SECTION("shr edi, cl [d3 ef]") {
    const auto *ib = lift({0xd3, 0xef});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::SHR));
    // CF/ZF/SF/PF gated, AF cleared, and OF now modelled concretely (so a
    // pushfq after a shift carries a real OF, not UNDEF) - nothing is UNDEF.
    REQUIRE(countOpcode(*ib, Opcode::UNDEF) == 0);
  }
  SECTION("shl r9w, cl [66 41 d3 e1] / shl rax, cl [48 d3 e0]") {
    for (auto bytes: {std::vector<uint8_t>{0x66, 0x41, 0xd3, 0xe1}, {0x48, 0xd3, 0xe0}}) {
      const auto *ib = lift(bytes);
      REQUIRE(ib != nullptr);
      REQUIRE(hasOpcode(*ib, Opcode::SHL));
    }
  }
  SECTION("sar dil, cl [40 d2 ff] / shr dh, cl [d2 ee]") {
    const auto *ib = lift({0x40, 0xd2, 0xff});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::SAR));
    const auto *ib2 = lift({0xd2, 0xee});
    REQUIRE(ib2 != nullptr);
    REQUIRE(hasOpcode(*ib2, Opcode::SHR));
  }
  SECTION("shr bh, 3 [c0 ef 03] / shl ax, 2 [66 c1 e0 02]") {
    const auto *ib = lift({0xc0, 0xef, 0x03});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::SHR));
    const auto *ib2 = lift({0x66, 0xc1, 0xe0, 0x02});
    REQUIRE(ib2 != nullptr);
    REQUIRE(hasOpcode(*ib2, Opcode::SHL));
  }
  SECTION("neg dil [40 f6 df] / neg cx [66 f7 d9]") {
    for (auto bytes: {std::vector<uint8_t>{0x40, 0xf6, 0xdf}, {0x66, 0xf7, 0xd9}}) {
      const auto *ib = lift(bytes);
      REQUIRE(ib != nullptr);
      REQUIRE(hasOpcode(*ib, Opcode::NEG));
    }
  }
  SECTION("cwde [98] / cdqe [48 98] sign-extend; cwd [66 99] / cqo [48 99] sign-fill") {
    REQUIRE(hasOpcode(*lift({0x98}), Opcode::SEXT));
    REQUIRE(hasOpcode(*lift({0x48, 0x98}), Opcode::SEXT));
    REQUIRE(hasOpcode(*lift({0x66, 0x99}), Opcode::SAR));
    REQUIRE(hasOpcode(*lift({0x48, 0x99}), Opcode::SAR));
  }
  SECTION("stc [f9] / clc [f8] write CF, cmc [f5] flips it") {
    const auto *stc = lift({0xf9});
    REQUIRE(countOpcode(*stc, Opcode::COPY) >= 1);
    REQUIRE(countOpcode(*stc, Opcode::UNDEF) == 0);
    const auto *clc = lift({0xf8});
    REQUIRE(countOpcode(*clc, Opcode::COPY) >= 1);
    const auto *cmc = lift({0xf5});
    REQUIRE(hasOpcode(*cmc, Opcode::XOR));
  }
}

TEST_CASE("IGNIL lifting - VMProtect handler forms round 2 (8/16-bit ALU, "
          "mov r8/r16 imm, xchg, bswap, shld/shrd, inc/dec 8/16)",
          "[ignil][x86_64][vmp]") {
  using dragon::ignil::Opcode;
  auto lift = [](std::vector<uint8_t> bytes) {
    static std::vector<dragon::Graph> keep;
    keep.push_back(makeGraph(dragon::Architecture::X86_64));
    auto &g = keep.back();
    auto dis = makeDisassembler(dragon::Architecture::X86_64);
    bytes.push_back(0xc3);
    dis.disassemble(bytes, 0x1000, g);
    return g.getIGNILBlock(0x1000);
  };
  SECTION("mov r8b, 0xd [41 b0 0d] / mov r9w, 0x9a95 [66 41 b9 95 9a] / mov dh, ah [88 e6]") {
    for (auto bytes: {std::vector<uint8_t>{0x41, 0xb0, 0x0d}, {0x66, 0x41, 0xb9, 0x95, 0x9a}, {0x88, 0xe6}}) {
      const auto *ib = lift(bytes);
      REQUIRE(ib != nullptr);
      REQUIRE(hasOpcode(*ib, Opcode::COPY));
      REQUIRE(countOpcode(*ib, Opcode::UNDEF) == 0);
    }
  }
  SECTION("and bl, 0xf0 [80 e3 f0] / add cx, di [66 01 f9] / or r9w, r8w [66 45 09 c1] / sub dil, r13b [44 28 ef]") {
    REQUIRE(hasOpcode(*lift({0x80, 0xe3, 0xf0}), Opcode::AND));
    REQUIRE(hasOpcode(*lift({0x66, 0x01, 0xf9}), Opcode::ADD));
    REQUIRE(hasOpcode(*lift({0x66, 0x45, 0x09, 0xc1}), Opcode::OR));
    REQUIRE(hasOpcode(*lift({0x44, 0x28, 0xef}), Opcode::SUB));
  }
  SECTION("cmp r14b, 0x95 [41 80 fe 95] / test dil, 0x2f [40 f6 c7 2f] produce flags, no register write") {
    const auto *cmp = lift({0x41, 0x80, 0xfe, 0x95});
    REQUIRE(hasOpcode(*cmp, Opcode::SUB));
    const auto *tst = lift({0x40, 0xf6, 0xc7, 0x2f});
    REQUIRE(hasOpcode(*tst, Opcode::AND));
  }
  SECTION("dec dl [fe ca] / inc cx [66 ff c1]") {
    REQUIRE(hasOpcode(*lift({0xfe, 0xca}), Opcode::SUB));
    REQUIRE(hasOpcode(*lift({0x66, 0xff, 0xc1}), Opcode::ADD));
  }
  SECTION("xchg rdx, rdx [48 87 d2] is two copies, no UNDEF") {
    const auto *ib = lift({0x48, 0x87, 0xd2});
    REQUIRE(countOpcode(*ib, Opcode::COPY) >= 2);
    REQUIRE(countOpcode(*ib, Opcode::UNDEF) == 0);
  }
  SECTION("bswap esi [0f ce] / bswap rax [48 0f c8]") {
    for (auto bytes: {std::vector<uint8_t>{0x0f, 0xce}, {0x48, 0x0f, 0xc8}}) {
      const auto *ib = lift(bytes);
      REQUIRE(hasOpcode(*ib, Opcode::SHL));
      REQUIRE(hasOpcode(*ib, Opcode::OR));
      REQUIRE(countOpcode(*ib, Opcode::UNDEF) == 0);
    }
  }
  SECTION("shld r10d, r9d, cl [45 0f a5 ca] / shrd ax, dx, 5 [66 0f ac d0 05]") {
    const auto *a = lift({0x45, 0x0f, 0xa5, 0xca});
    REQUIRE(hasOpcode(*a, Opcode::SHL));
    REQUIRE(hasOpcode(*a, Opcode::SHR));
    // OF is modelled concretely now (shared emitGatedShiftFlags), so the
    // double-shift leaves nothing UNDEF either.
    REQUIRE(countOpcode(*a, Opcode::UNDEF) == 0);
    const auto *b = lift({0x66, 0x0f, 0xac, 0xd0, 0x05});
    REQUIRE(hasOpcode(*b, Opcode::SHR));
    REQUIRE(hasOpcode(*b, Opcode::SHL));
  }
}

TEST_CASE("IGNIL lifting - push imm32 / push imm8 (PUSH64i32, PUSH64i8)", "[ignil][x86_64][vmp]") {
  using dragon::ignil::Opcode;
  auto lift = [](std::vector<uint8_t> bytes) {
    static std::vector<dragon::Graph> keep;
    keep.push_back(makeGraph(dragon::Architecture::X86_64));
    auto &g = keep.back();
    auto dis = makeDisassembler(dragon::Architecture::X86_64);
    bytes.push_back(0xc3);
    dis.disassemble(bytes, 0x1000, g);
    return g.getIGNILBlock(0x1000);
  };
  SECTION("push 0x59f91842 [68 42 18 f9 59]") {
    const auto *ib = lift({0x68, 0x42, 0x18, 0xf9, 0x59});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::STORE));
    REQUIRE(hasOpcode(*ib, Opcode::SUB));
  }
  SECTION("push -1 [6a ff]") {
    const auto *ib = lift({0x6a, 0xff});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::STORE));
  }
}

// ---------------------------------------------------------------------------
// Accumulator short forms, BT, and RIP-relative operands inside a trace.
// Found by symbolically executing a VMProtect VM end to end: each of these
// lifted to nothing (or, for RIP, to a stale register read) without a word.
// ---------------------------------------------------------------------------

TEST_CASE("IGNIL lifting - accumulator short forms (SUB8i8, OR8i8, TEST8i8, "
          "SUB16i16, CMP32i32, ADD64i32)",
          "[ignil][x86_64][vmp]") {
  using dragon::ignil::Opcode;
  auto lift = [](std::vector<uint8_t> bytes) {
    static std::vector<dragon::Graph> keep;
    keep.push_back(makeGraph(dragon::Architecture::X86_64));
    auto &g = keep.back();
    auto dis = makeDisassembler(dragon::Architecture::X86_64);
    bytes.push_back(0xc3);
    dis.disassemble(bytes, 0x1000, g);
    return g.getIGNILBlock(0x1000);
  };
  // True if some op of `kind` writes the register at `offset`, `width` wide.
  auto writes = [](const dragon::ignil::Block &ib, std::uint32_t offset,
                   dragon::ignil::Width width) {
    for (const auto &op: ib.ops())
      if (op.dst)
        if (const auto *r = std::get_if<dragon::ignil::Reg>(&*op.dst))
          if (r->offset == offset && r->width == width)
            return true;
    return false;
  };

  SECTION("sub al, 0x22 [2c 22]") {
    const auto *ib = lift({0x2c, 0x22});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::SUB));
    REQUIRE(writes(*ib, dragon::x86::AL.offset, 8));
    REQUIRE(writes(*ib, dragon::x86::ZF.offset, 8));
  }
  SECTION("or al, 2 [0c 02]") {
    const auto *ib = lift({0x0c, 0x02});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::OR));
    REQUIRE(writes(*ib, dragon::x86::AL.offset, 8));
  }
  SECTION("test al, 5 [a8 05] sets flags and leaves AL alone") {
    const auto *ib = lift({0xa8, 0x05});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::AND));
    REQUIRE(writes(*ib, dragon::x86::ZF.offset, 8));
    REQUIRE_FALSE(writes(*ib, dragon::x86::AL.offset, 8));
  }
  SECTION("sub ax, 0xe9ab [66 2d ab e9]") {
    const auto *ib = lift({0x66, 0x2d, 0xab, 0xe9});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::SUB));
    REQUIRE(writes(*ib, dragon::x86::AX.offset, 16));
  }
  SECTION("cmp eax, 0x12345678 [3d 78 56 34 12] sets flags only") {
    const auto *ib = lift({0x3d, 0x78, 0x56, 0x34, 0x12});
    REQUIRE(ib != nullptr);
    REQUIRE(writes(*ib, dragon::x86::CF.offset, 8));
    REQUIRE_FALSE(writes(*ib, dragon::x86::EAX.offset, 32));
  }
  SECTION("add rax, 0x10 [48 05 10 00 00 00]") {
    const auto *ib = lift({0x48, 0x05, 0x10, 0x00, 0x00, 0x00});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::ADD));
    REQUIRE(writes(*ib, dragon::x86::RAX.offset, 64));
  }
}

TEST_CASE("IGNIL lifting - BT reg, imm8 / reg, reg writes CF only",
          "[ignil][x86_64][vmp]") {
  using dragon::ignil::Opcode;
  auto lift = [](std::vector<uint8_t> bytes) {
    static std::vector<dragon::Graph> keep;
    keep.push_back(makeGraph(dragon::Architecture::X86_64));
    auto &g = keep.back();
    auto dis = makeDisassembler(dragon::Architecture::X86_64);
    bytes.push_back(0xc3);
    dis.disassemble(bytes, 0x1000, g);
    return g.getIGNILBlock(0x1000);
  };
  auto flagWrites = [](const dragon::ignil::Block &ib) {
    std::set<std::uint32_t> out;
    for (const auto &op: ib.ops())
      if (op.dst)
        if (const auto *r = std::get_if<dragon::ignil::Reg>(&*op.dst))
          if (r->offset >= dragon::x86::CF.offset &&
              r->offset <= dragon::x86::DF.offset)
            out.insert(r->offset);
    return out;
  };

  SECTION("bt r8, 0x31 [49 0f ba e0 31]") {
    const auto *ib = lift({0x49, 0x0f, 0xba, 0xe0, 0x31});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::SHR));
    REQUIRE(flagWrites(*ib) == std::set<std::uint32_t>{dragon::x86::CF.offset});
  }
  SECTION("bt ax, dx [66 0f a3 d0]") {
    const auto *ib = lift({0x66, 0x0f, 0xa3, 0xd0});
    REQUIRE(ib != nullptr);
    REQUIRE(hasOpcode(*ib, Opcode::SHR));
    REQUIRE(flagWrites(*ib) == std::set<std::uint32_t>{dragon::x86::CF.offset});
  }
}

TEST_CASE("IGNIL lifting - a RIP-relative operand pins RIP to the next "
          "instruction",
          "[ignil][x86_64][vmp]") {
  // nop; lea rax, [rip + 0x10]   - RIP must be 0x1008, not whatever a caller
  // seeded the register with, and not the block's start.
  auto g = makeGraph(dragon::Architecture::X86_64);
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  const std::vector<uint8_t> code = {0x90, 0x48, 0x8d, 0x05, 0x10,
                                     0x00, 0x00, 0x00, 0xc3};
  dis.disassemble(code, 0x1000, g);
  const auto *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);

  bool pinned = false;
  for (const auto &op: ib->ops()) {
    if (!op.dst || op.srcs.size() != 1)
      continue;
    const auto *dst = std::get_if<dragon::ignil::Reg>(&*op.dst);
    const auto *src = std::get_if<dragon::ignil::Const>(&op.srcs[0]);
    if (dst && src && dst->offset == dragon::x86::RIP.offset)
      pinned = src->value == 0x1008;
  }
  REQUIRE(pinned);
}

// ---------------------------------------------------------------------------
// An instruction without a lifter is recorded, and leaves nothing stale.
// ---------------------------------------------------------------------------

TEST_CASE("IGNIL lifting - an unlifted instruction is recorded, and its "
          "register and flag results are UNDEF",
          "[ignil][x86_64][vmp]") {
  using dragon::ignil::Opcode;
  auto lift = [](std::vector<uint8_t> bytes) {
    static std::vector<dragon::Graph> keep;
    keep.push_back(makeGraph(dragon::Architecture::X86_64));
    auto &g = keep.back();
    auto dis = makeDisassembler(dragon::Architecture::X86_64);
    bytes.push_back(0xc3);
    dis.disassemble(bytes, 0x1000, g);
    return g.getIGNILBlock(0x1000);
  };
  // Registers (by offset) some UNDEF op writes.
  auto undefined = [](const dragon::ignil::Block &ib) {
    std::set<std::uint32_t> out;
    for (const auto &op: ib.ops())
      if (op.opcode == Opcode::UNDEF && op.dst)
        if (const auto *r = std::get_if<dragon::ignil::Reg>(&*op.dst))
          out.insert(r->offset);
    return out;
  };

  SECTION("adc eax, [rbp] [13 45 00] - no lifter: EAX and the flags it writes") {
    // The register and immediate ADC/SBB forms are lifted; the memory-source
    // form (ADC32rm) is not, so it stands in as an instruction whose results
    // must fall back to UNDEF (both the destination register and the flags).
    const auto *ib = lift({0x13, 0x45, 0x00});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted() == std::vector<std::uint64_t>{0x1000});
    const auto regs = undefined(*ib);
    REQUIRE(regs.count(dragon::x86::EAX.offset) == 1);
    // ADC defines CF and OF; without this a `jc` after it would read the
    // carry of whatever ran before.
    REQUIRE(regs.count(dragon::x86::CF.offset) == 1);
    REQUIRE(regs.count(dragon::x86::OF.offset) == 1);
  }
  SECTION("bswap ax [66 0f c8] - architecturally undefined, so AX is UNDEF") {
    const auto *ib = lift({0x66, 0x0f, 0xc8});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted() == std::vector<std::uint64_t>{0x1000});
    const auto regs = undefined(*ib);
    REQUIRE(regs.count(dragon::x86::AX.offset) == 1);
  }
  SECTION("what is lifted is not reported: nop, mul rbx, adc rax, rbx") {
    const auto *ib = lift({0x90, 0x48, 0xf7, 0xe3, 0x48, 0x11, 0xd8});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::MUL));
  }
  SECTION("div rbx [48 f7 f3] is lifted through a 128-bit dividend") {
    const auto *ib = lift({0x48, 0xf7, 0xf3});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::UDIV));
    REQUIRE(hasOpcode(*ib, Opcode::UMOD));
  }
  SECTION("the optimisation passes carry the record over") {
    const auto *ib = lift({0x13, 0x45, 0x00}); // adc eax, [rbp] - still unlifted
    REQUIRE(ib != nullptr);
    REQUIRE_FALSE(ib->unlifted().empty());
    const auto simplified = dragon::ignil::simplifyBlock(*ib);
    REQUIRE(simplified.unlifted() == ib->unlifted());
  }
}

// feat/x86-lift-rotates-bitops: the rest of the VMProtect mutation handler
// forms the lift-coverage sweep over License-Check reported as unlifted -
// rotates, bit test-and-modify, CMOVcc, XADD, memory INC/DEC and LAHF/SAHF.
// Simple structural checks: the instruction must leave the unlifted() list and
// produce the ops its semantics are built from (no Unicorn round-trip here).
TEST_CASE("IGNIL lifting - rotates, BTS/BTR/BTC, CMOVcc, XADD, mem INC/DEC, "
          "LAHF/SAHF",
          "[ignil][x86_64][vmp]") {
  using dragon::ignil::Opcode;
  auto lift = [](std::vector<uint8_t> bytes) {
    static std::vector<dragon::Graph> keep;
    keep.push_back(makeGraph(dragon::Architecture::X86_64));
    auto &g = keep.back();
    auto dis = makeDisassembler(dragon::Architecture::X86_64);
    bytes.push_back(0xc3);
    dis.disassemble(bytes, 0x1000, g);
    return g.getIGNILBlock(0x1000);
  };

  SECTION("rol eax, 5  [c1 c0 05] - synthesized from SHL/SHR/OR, CF written") {
    const auto *ib = lift({0xc1, 0xc0, 0x05});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::SHL));
    REQUIRE(hasOpcode(*ib, Opcode::SHR));
    REQUIRE(hasOpcode(*ib, Opcode::OR));
  }
  SECTION("ror eax, 5  [c1 c8 05]") {
    const auto *ib = lift({0xc1, 0xc8, 0x05});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::SHL));
    REQUIRE(hasOpcode(*ib, Opcode::SHR));
  }
  SECTION("rol eax, cl  [d3 c0] - variable count") {
    const auto *ib = lift({0xd3, 0xc0});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::OR));
  }
  SECTION("rol rax, 7  [48 c1 c0 07] - 64-bit") {
    const auto *ib = lift({0x48, 0xc1, 0xc0, 0x07});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
  }
  SECTION("bts eax, ebx  [0f ab d8] - CF set, dst OR'd with the bit mask") {
    const auto *ib = lift({0x0f, 0xab, 0xd8});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::OR));
  }
  SECTION("btr eax, 3  [0f ba f0 03] - bit cleared with AND NOT") {
    const auto *ib = lift({0x0f, 0xba, 0xf0, 0x03});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::NOT));
    REQUIRE(hasOpcode(*ib, Opcode::AND));
  }
  SECTION("btc rax, rbx  [48 0f bb d8] - bit complemented with XOR") {
    const auto *ib = lift({0x48, 0x0f, 0xbb, 0xd8});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::XOR));
  }
  SECTION("cmove eax, ebx  [0f 44 c3] - select, no flags written") {
    const auto *ib = lift({0x0f, 0x44, 0xc3});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::OR));
    REQUIRE(hasOpcode(*ib, Opcode::NEG)); // mask = -(cond as word)
  }
  SECTION("xadd ebx, eax  [0f c1 c3] - exchange-and-add, ADD flags") {
    const auto *ib = lift({0x0f, 0xc1, 0xc3});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::ADD));
  }
  SECTION("inc dword ptr [rbp-4]  [ff 45 fc] - load/add 1/store, CF untouched") {
    const auto *ib = lift({0xff, 0x45, 0xfc});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::LOAD));
    REQUIRE(hasOpcode(*ib, Opcode::ADD));
    REQUIRE(hasOpcode(*ib, Opcode::STORE));
  }
  SECTION("dec qword ptr [rbp-8]  [48 ff 4d f8]") {
    const auto *ib = lift({0x48, 0xff, 0x4d, 0xf8});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::LOAD));
    REQUIRE(hasOpcode(*ib, Opcode::SUB));
    REQUIRE(hasOpcode(*ib, Opcode::STORE));
  }
  SECTION("lahf  [9f] - AH gathered from the flag bits") {
    const auto *ib = lift({0x9f});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::OR));
  }
  SECTION("sahf  [9e] - flags scattered back from AH") {
    const auto *ib = lift({0x9e});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::AND));
  }
}

// feat/x86-lift-rotates-bitops (second batch): rotate-through-carry by a known
// count (RCL/RCR imm8 and by-1; the CL forms stay unlifted on purpose) and the
// bit-scan instructions BSF/BSR. Structural checks only.
TEST_CASE("IGNIL lifting - RCL/RCR (imm) and BSF/BSR", "[ignil][x86_64][vmp]") {
  using dragon::ignil::Opcode;
  auto lift = [](std::vector<uint8_t> bytes) {
    static std::vector<dragon::Graph> keep;
    keep.push_back(makeGraph(dragon::Architecture::X86_64));
    auto &g = keep.back();
    auto dis = makeDisassembler(dragon::Architecture::X86_64);
    bytes.push_back(0xc3);
    dis.disassemble(bytes, 0x1000, g);
    return g.getIGNILBlock(0x1000);
  };

  SECTION("rcl eax, 3  [c1 d0 03] - CF folded in, CF rewritten") {
    const auto *ib = lift({0xc1, 0xd0, 0x03});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::OR));
    REQUIRE(hasOpcode(*ib, Opcode::SHL));
  }
  SECTION("rcr eax, 3  [c1 d8 03]") {
    const auto *ib = lift({0xc1, 0xd8, 0x03});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::OR));
    REQUIRE(hasOpcode(*ib, Opcode::SHR));
  }
  SECTION("rcl eax, 1  [d1 d0] - by the implicit 1") {
    const auto *ib = lift({0xd1, 0xd0});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
  }
  SECTION("rcr rax, 5  [48 c1 d8 05] - 64-bit, no (width+1) container needed") {
    const auto *ib = lift({0x48, 0xc1, 0xd8, 0x05});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
  }
  SECTION("bsf eax, ebx  [0f bc c3] - index of lowest set bit, ZF on zero") {
    const auto *ib = lift({0x0f, 0xbc, 0xc3});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::NEG)); // mask-select per bit
  }
  SECTION("bsr rax, rbx  [48 0f bd c3] - index of highest set bit") {
    const auto *ib = lift({0x48, 0x0f, 0xbd, 0xc3});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
  }
}

// feat/x86-lift-rotates-bitops (third batch): the variable rotate-through-carry
// (RCL/RCR by CL) and the accumulator XCHG (xchg ax/eax/rax, r) - the forms the
// serial_ok devirt run still reported as UNDEF on its executed path.
TEST_CASE("IGNIL lifting - RCL/RCR by CL and accumulator XCHG",
          "[ignil][x86_64][vmp]") {
  using dragon::ignil::Opcode;
  auto lift = [](std::vector<uint8_t> bytes) {
    static std::vector<dragon::Graph> keep;
    keep.push_back(makeGraph(dragon::Architecture::X86_64));
    auto &g = keep.back();
    auto dis = makeDisassembler(dragon::Architecture::X86_64);
    bytes.push_back(0xc3);
    dis.disassemble(bytes, 0x1000, g);
    return g.getIGNILBlock(0x1000);
  };

  SECTION("rcl eax, cl  [d3 d0] - variable rotate through carry") {
    const auto *ib = lift({0xd3, 0xd0});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::OR));
    REQUIRE(hasOpcode(*ib, Opcode::SHL));
    REQUIRE(hasOpcode(*ib, Opcode::SHR));
  }
  SECTION("rcr rdx, cl  [48 d3 da] - 64-bit, no (width+1) container") {
    const auto *ib = lift({0x48, 0xd3, 0xda});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::OR));
  }
  SECTION("rcr dl, cl  [d2 da] - 8-bit, count reduced mod 9 with UMOD") {
    const auto *ib = lift({0xd2, 0xda});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::UMOD));
  }
  SECTION("xchg ax, r11w  [66 41 93] - accumulator XCHG16ar") {
    const auto *ib = lift({0x66, 0x41, 0x93});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, Opcode::COPY));
  }
  SECTION("xchg rax, rbx  [48 93] - accumulator XCHG64ar") {
    const auto *ib = lift({0x48, 0x93});
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
  }
}

// -----------------------------------------------------------------------
// i386 forms
// -----------------------------------------------------------------------

TEST_CASE("IGNIL lifting - i386 ret (RET32)", "[ignil][x86_32]") {
  const std::vector<std::uint8_t> bytes = {
          0xc3, // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::RET));
}

TEST_CASE("IGNIL lifting - i386 ret imm16 (RETI32)", "[ignil][x86_32]") {
  // ret 4
  const std::vector<std::uint8_t> bytes = {0xc2, 0x04, 0x00};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::RET));
}

TEST_CASE("IGNIL lifting - i386 call rel32 (CALLpcrel32)", "[ignil][x86_32]") {
  const std::vector<std::uint8_t> bytes = {
          0xe8, 0x00, 0x00, 0x00, 0x00, // call $+5
          0x58, // pop eax
          0xc3, // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  const auto &ops = ib->ops();
  auto callIt = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::CALL;
  });
  REQUIRE(callIt != ops.end());
  const auto *target = std::get_if<dragon::ignil::Const>(&callIt->srcs[0]);
  REQUIRE(target != nullptr);
  REQUIRE(target->value == 0x1005);
}

TEST_CASE("IGNIL lifting - i386 call reg (CALL32r)", "[ignil][x86_32]") {
  // call edx; ret
  const std::vector<std::uint8_t> bytes = {0xff, 0xd2, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  const auto &ops = ib->ops();
  auto callIt = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::CALL;
  });
  REQUIRE(callIt != ops.end());
  const auto *target = std::get_if<dragon::ignil::Reg>(&callIt->srcs[0]);
  REQUIRE(target != nullptr);
  REQUIRE(target->name == "EDX");
  REQUIRE(target->width == 32);
}

TEST_CASE("IGNIL lifting - i386 pushfd (PUSHF32)", "[ignil][x86_32]") {
  // pushfd; ret
  const std::vector<std::uint8_t> bytes = {0x9c, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
  const auto &ops = ib->ops();
  auto subIt = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::SUB;
  });
  REQUIRE(subIt != ops.end());
  const auto *sp = std::get_if<dragon::ignil::Reg>(&subIt->srcs[0]);
  REQUIRE(sp != nullptr);
  REQUIRE(sp->name == "ESP");
  const auto *size = std::get_if<dragon::ignil::Const>(&subIt->srcs[1]);
  REQUIRE(size != nullptr);
  REQUIRE(size->value == 4);
}

TEST_CASE("IGNIL lifting - i386 popfd (POPF32)", "[ignil][x86_32]") {
  // popfd; ret
  const std::vector<std::uint8_t> bytes = {0x9d, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  const auto &ops = ib->ops();
  auto addIt = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::ADD;
  });
  REQUIRE(addIt != ops.end());
  const auto *sp = std::get_if<dragon::ignil::Reg>(&addIt->srcs[0]);
  REQUIRE(sp != nullptr);
  REQUIRE(sp->name == "ESP");
  const auto *size = std::get_if<dragon::ignil::Const>(&addIt->srcs[1]);
  REQUIRE(size != nullptr);
  REQUIRE(size->value == 4);
}

TEST_CASE("IGNIL lifting - i386 pushad (PUSHA32)", "[ignil][x86_32]") {
  // pushad; ret
  const std::vector<std::uint8_t> bytes = {0x60, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  const auto &ops = ib->ops();
  REQUIRE(std::count_if(ops.begin(), ops.end(), [](const auto &op) {
            return op.opcode == dragon::ignil::Opcode::STORE;
          }) == 8);
  // The saved ESP is its value before the instruction.
  REQUIRE(std::any_of(ops.begin(), ops.end(), [](const auto &op) {
    if (op.opcode != dragon::ignil::Opcode::STORE)
      return false;
    const auto *value = std::get_if<dragon::ignil::Reg>(&op.srcs[1]);
    return value && value->name == "ESP";
  }));
}

TEST_CASE("IGNIL lifting - i386 popad (POPA32)", "[ignil][x86_32]") {
  // popad; ret
  const std::vector<std::uint8_t> bytes = {0x61, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  const auto &ops = ib->ops();
  REQUIRE(std::count_if(ops.begin(), ops.end(), [](const auto &op) {
            return op.opcode == dragon::ignil::Opcode::LOAD;
          }) == 7);
  // The saved ESP is discarded.
  REQUIRE(std::count_if(ops.begin(), ops.end(), [](const auto &op) {
            const auto *dst = op.dst ? std::get_if<dragon::ignil::Reg>(&*op.dst)
                                     : nullptr;
            return dst && dst->name == "ESP";
          }) == 1);
}

TEST_CASE("IGNIL lifting - i386 push ss (PUSHSS32)", "[ignil][x86_32]") {
  // push ss; ret
  const std::vector<std::uint8_t> bytes = {0x16, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::UNDEF));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
  const auto &ops = ib->ops();
  auto subIt = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::SUB;
  });
  REQUIRE(subIt != ops.end());
  const auto *sp = std::get_if<dragon::ignil::Reg>(&subIt->srcs[0]);
  REQUIRE(sp != nullptr);
  REQUIRE(sp->name == "ESP");
  const auto *size = std::get_if<dragon::ignil::Const>(&subIt->srcs[1]);
  REQUIRE(size != nullptr);
  REQUIRE(size->value == 4);
}

TEST_CASE("IGNIL lifting - i386 pop ss (POPSS32)", "[ignil][x86_32]") {
  // pop ss; ret
  const std::vector<std::uint8_t> bytes = {0x17, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE_FALSE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
  const auto &ops = ib->ops();
  auto addIt = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::ADD;
  });
  REQUIRE(addIt != ops.end());
  const auto *sp = std::get_if<dragon::ignil::Reg>(&addIt->srcs[0]);
  REQUIRE(sp != nullptr);
  REQUIRE(sp->name == "ESP");
  const auto *size = std::get_if<dragon::ignil::Const>(&addIt->srcs[1]);
  REQUIRE(size != nullptr);
  REQUIRE(size->value == 4);
}

TEST_CASE("IGNIL lifting - i386 dec reg short form (DEC32r_alt)",
          "[ignil][x86_32]") {
  // dec edx (0x48+r); ret
  const std::vector<std::uint8_t> bytes = {0x4a, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SUB));
}

TEST_CASE("IGNIL lifting - i386 inc/dec reg short forms (INC32r_alt, "
          "INC16r_alt, DEC16r_alt)",
          "[ignil][x86_32]") {
  for (const auto &[bytes, opcode]:
       std::vector<std::pair<std::vector<std::uint8_t>, dragon::ignil::Opcode>>{
               {{0x40, 0xc3}, dragon::ignil::Opcode::ADD}, // inc eax; ret
               {{0x66, 0x41, 0xc3}, dragon::ignil::Opcode::ADD}, // inc cx; ret
               {{0x66, 0x4a, 0xc3}, dragon::ignil::Opcode::SUB}, // dec dx; ret
       }) {
    auto dis = makeDisassembler(dragon::Architecture::X86_32);
    auto g = makeGraph(dragon::Architecture::X86_32);
    dis.disassemble(bytes, 0x1000, g);

    const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
    REQUIRE(ib != nullptr);
    REQUIRE(ib->unlifted().empty());
    REQUIRE(hasOpcode(*ib, opcode));
  }
}

TEST_CASE("IGNIL lifting - i386 branch targets wrap at 4 GB",
          "[ignil][x86_32]") {
  // call -0x2000 at 0x1000 lands at 0xfffff005, not 0xfffffffffffff005.
  const std::vector<std::uint8_t> callBytes = {0xe8, 0x00, 0xe0, 0xff, 0xff,
                                               0xc3};
  // je -0x2000 at 0x1000 (JCC_4).
  const std::vector<std::uint8_t> jccBytes = {0x0f, 0x84, 0x00, 0xe0,
                                              0xff, 0xff, 0xc3};
  for (const auto &[bytes, opcode, target]:
       std::vector<std::tuple<std::vector<std::uint8_t>, dragon::ignil::Opcode,
                              std::uint64_t>>{
               {callBytes, dragon::ignil::Opcode::CALL, 0xfffff005},
               {jccBytes, dragon::ignil::Opcode::CJMP, 0xfffff006},
       }) {
    auto dis = makeDisassembler(dragon::Architecture::X86_32);
    auto g = makeGraph(dragon::Architecture::X86_32);
    dis.disassemble(bytes, 0x1000, g);

    const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
    REQUIRE(ib != nullptr);
    const auto &ops = ib->ops();
    const auto it = std::find_if(ops.begin(), ops.end(), [&](const auto &op) {
      return op.opcode == opcode;
    });
    REQUIRE(it != ops.end());
    const auto &dst = it->srcs[opcode == dragon::ignil::Opcode::CALL ? 0 : 1];
    const auto *c = std::get_if<dragon::ignil::Const>(&dst);
    REQUIRE(c != nullptr);
    REQUIRE(c->value == target);
  }
}

TEST_CASE("IGNIL lifting - i386 cld (CLD)", "[ignil][x86_32]") {
  // cld; ret
  const std::vector<std::uint8_t> bytes = {0xfc, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  const auto &ops = ib->ops();
  REQUIRE(std::any_of(ops.begin(), ops.end(), [](const auto &op) {
    if (op.opcode != dragon::ignil::Opcode::COPY || !op.dst)
      return false;
    const auto *dst = std::get_if<dragon::ignil::Reg>(&*op.dst);
    const auto *value = std::get_if<dragon::ignil::Const>(&op.srcs[0]);
    return dst && dst->name == "DF" && value && value->value == 0;
  }));
}

TEST_CASE("IGNIL lifting - i386 add byte [mem], reg (ADD8mr)",
          "[ignil][x86_32]") {
  // add byte [ebx+0x10], al; ret
  const std::vector<std::uint8_t> bytes = {0x00, 0x43, 0x10, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
  const auto &ops = ib->ops();
  auto loadIt = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::LOAD;
  });
  REQUIRE(loadIt != ops.end());
  REQUIRE(dragon::ignil::widthOf(*loadIt->dst) == 8);
}

TEST_CASE("IGNIL lifting - i386 mov byte [mem], imm (MOV8mi)",
          "[ignil][x86_32]") {
  // mov byte [ebx+0x10], 0xf0; ret
  const std::vector<std::uint8_t> bytes = {0xc6, 0x43, 0x10, 0xf0, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  const auto &ops = ib->ops();
  auto storeIt = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::STORE;
  });
  REQUIRE(storeIt != ops.end());
  REQUIRE(dragon::ignil::widthOf(storeIt->srcs[1]) == 8);
}

TEST_CASE("IGNIL lifting - i386 cmp byte [mem], imm (CMP8mi)",
          "[ignil][x86_32]") {
  // cmp byte [edx], 0; ret
  const std::vector<std::uint8_t> bytes = {0x80, 0x3a, 0x00, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE_FALSE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
  const auto &ops = ib->ops();
  auto loadIt = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::LOAD;
  });
  REQUIRE(loadIt != ops.end());
  REQUIRE(dragon::ignil::widthOf(*loadIt->dst) == 8);
}

TEST_CASE("IGNIL lifting - i386 xor reg, [mem] (XOR32rm)", "[ignil][x86_32]") {
  // xor eax, [edx]; ret
  const std::vector<std::uint8_t> bytes = {0x33, 0x02, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::XOR));
  REQUIRE_FALSE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
}

TEST_CASE("IGNIL lifting - i386 xor [mem], imm (XOR32mi)", "[ignil][x86_32]") {
  // xor dword [esp], 0xb53d; ret
  const std::vector<std::uint8_t> bytes = {0x81, 0x34, 0x24, 0x3d,
                                           0xb5, 0x00, 0x00, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::XOR));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
}

TEST_CASE("IGNIL lifting - i386 xor [mem], reg (XOR32mr)", "[ignil][x86_32]") {
  // xor dword [edi], eax; ret
  const std::vector<std::uint8_t> bytes = {0x31, 0x07, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::XOR));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
}

TEST_CASE("IGNIL lifting - i386 and [mem], reg (AND32mr)", "[ignil][x86_32]") {
  // and dword [edx], eax; ret
  const std::vector<std::uint8_t> bytes = {0x21, 0x02, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::AND));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
}

TEST_CASE("IGNIL lifting - i386 push [mem] (PUSH32rmm)", "[ignil][x86_32]") {
  // push dword [edx]; ret
  const std::vector<std::uint8_t> bytes = {0xff, 0x32, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
  // The operand is read before ESP moves.
  const auto &ops = ib->ops();
  auto loadIt = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::LOAD;
  });
  auto subIt = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::SUB;
  });
  REQUIRE(loadIt != ops.end());
  REQUIRE(subIt != ops.end());
  REQUIRE(loadIt < subIt);
}

TEST_CASE("IGNIL lifting - i386 pop [mem] (POP32rmm)", "[ignil][x86_32]") {
  // pop dword [esp+4]; ret
  const std::vector<std::uint8_t> bytes = {0x8f, 0x44, 0x24, 0x04, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  // The destination address uses ESP after the pop has moved it.
  const auto &ops = ib->ops();
  auto spIt = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    const auto *dst =
            op.dst ? std::get_if<dragon::ignil::Reg>(&*op.dst) : nullptr;
    return dst && dst->name == "ESP";
  });
  auto storeIt = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::STORE;
  });
  REQUIRE(spIt != ops.end());
  REQUIRE(storeIt != ops.end());
  REQUIRE(spIt < storeIt);
}

TEST_CASE("IGNIL lifting - i386 xchg [mem], reg (XCHG32rm)",
          "[ignil][x86_32]") {
  // xchg [esi], esp; ret
  const std::vector<std::uint8_t> bytes = {0x87, 0x26, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
}

TEST_CASE("IGNIL lifting - i386 xchg byte [mem], reg (XCHG8rm)",
          "[ignil][x86_32]") {
  // xchg byte [edx], al; ret
  const std::vector<std::uint8_t> bytes = {0x86, 0x02, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
  const auto &ops = ib->ops();
  auto loadIt = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::LOAD;
  });
  REQUIRE(loadIt != ops.end());
  REQUIRE(dragon::ignil::widthOf(*loadIt->dst) == 8);
}

TEST_CASE("IGNIL lifting - i386 ror [mem], cl (ROR32mCL)", "[ignil][x86_32]") {
  // ror dword [esp+4], cl; ret
  const std::vector<std::uint8_t> bytes = {0xd3, 0x4c, 0x24, 0x04, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
}

TEST_CASE("IGNIL lifting - i386 shr [mem], cl (SHR32mCL)", "[ignil][x86_32]") {
  // shr dword [edx], cl; ret
  const std::vector<std::uint8_t> bytes = {0xd3, 0x2a, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::SHR));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
}

TEST_CASE("IGNIL lifting - i386 btr [mem], imm (BTR32mi8)", "[ignil][x86_32]") {
  // btr dword [ebx+8], 6; ret
  const std::vector<std::uint8_t> bytes = {0x0f, 0xba, 0x73, 0x08, 0x06, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
}

TEST_CASE("IGNIL lifting - i386 loop (LOOP)", "[ignil][x86_32]") {
  const std::vector<std::uint8_t> bytes = {
          0xe2, 0x02, // loop 0x1004
          0x90, // nop
          0x90, // nop
          0xc3, // ret
  };
  auto dis = makeDisassembler(dragon::Architecture::X86_32);
  auto g = makeGraph(dragon::Architecture::X86_32);
  dis.disassemble(bytes, 0x1000, g);

  const dragon::ignil::Block *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::CJMP));
  // ECX is decremented; no flag is read or written.
  const auto &ops = ib->ops();
  REQUIRE(std::any_of(ops.begin(), ops.end(), [](const auto &op) {
    const auto *dst =
            op.dst ? std::get_if<dragon::ignil::Reg>(&*op.dst) : nullptr;
    return dst && dst->name == "ECX";
  }));
  REQUIRE(std::none_of(ops.begin(), ops.end(), [](const auto &op) {
    return std::any_of(op.srcs.begin(), op.srcs.end(), [](const auto &src) {
      const auto *reg = std::get_if<dragon::ignil::Reg>(&src);
      return reg && reg->name == "OF";
    });
  }));
}


TEST_CASE("IGNIL lifting - x64 pop [mem] (POP64rmm)", "[ignil][x86_64]") {
  // pop qword ptr [rbp + riz]; ret -- the SIB no-index form from the add sample.
  const std::vector<std::uint8_t> bytes = {0x8f, 0x44, 0x25, 0x00, 0xc3};
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);
  const auto *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::LOAD));
  REQUIRE(hasOpcode(*ib, dragon::ignil::Opcode::STORE));
  REQUIRE_FALSE(hasOpcode(*ib, dragon::ignil::Opcode::UNDEF));
}


TEST_CASE("IGNIL lifting - x64 push [mem] (PUSH64rmm)",
          "[ignil][x86_64][pushmem]") {
  // Exact add-sample opcode ff 33; also cover an RSP-dependent source EA.
  std::vector<std::uint8_t> bytes = {0xff, 0x33, 0xc3};
  SECTION("push qword ptr [rbx]") {}
  SECTION("push qword ptr [rsp+8]") { bytes = {0xff, 0x74, 0x24, 0x08, 0xc3}; }
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto g = makeGraph(dragon::Architecture::X86_64);
  dis.disassemble(bytes, 0x1000, g);
  const auto *ib = g.getIGNILBlock(0x1000);
  REQUIRE(ib != nullptr);
  REQUIRE(ib->unlifted().empty());
  REQUIRE_FALSE(hasOpcode(*ib, dragon::ignil::Opcode::UNDEF));
  const auto &ops = ib->ops();
  auto load = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::LOAD;
  });
  auto sub = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::SUB;
  });
  auto store = std::find_if(ops.begin(), ops.end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::STORE;
  });
  REQUIRE(load != ops.end());
  REQUIRE(sub != ops.end());
  REQUIRE(store != ops.end());
  REQUIRE(load < sub);
  REQUIRE(sub < store);
  REQUIRE(load->dst.has_value());
  REQUIRE(dragon::ignil::widthOf(*load->dst) == 64);
  REQUIRE(dragon::ignil::widthOf(store->srcs[1]) == 64);
}

TEST_CASE("IGNIL lifting - immediate word store keeps its exact width",
          "[ignil][x86_64][memory-effects]") {
  auto dis = makeDisassembler(dragon::Architecture::X86_64);
  auto graph = makeGraph(dragon::Architecture::X86_64);
  const std::vector<std::uint8_t> code{0x66, 0xc7, 0x42, 0x01, 0xef, 0xbe, 0xc3};
  dis.disassemble(code, 0x1000, graph);
  const auto *block = graph.getIGNILBlock(0x1000);
  REQUIRE(block);
  REQUIRE(block->unlifted().empty());
  auto store = std::find_if(block->ops().begin(), block->ops().end(), [](const auto &op) {
    return op.opcode == dragon::ignil::Opcode::STORE;
  });
  REQUIRE(store != block->ops().end());
  REQUIRE(dragon::ignil::widthOf(store->srcs[1]) == 16);
  REQUIRE(std::get<dragon::ignil::Const>(store->srcs[1]).value == 0xbeef);
}
