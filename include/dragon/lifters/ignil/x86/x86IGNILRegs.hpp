#pragma once

#include <dragon/lifters/ignil/IGNIL.hpp>

#include <cstdint>
#include <vector>

/// IGNIL register descriptors for the x86 / x86-64 architecture.
///
/// Every architectural register is represented as an ignil::Reg value:
///   - `offset` is its byte position in the IGNIL register address space.
///   - `width`  is the bit width.
///   - `name`   is the human-readable register name used in output.
///
/// Sub-registers share the same base offset as their parent 64-bit register,
/// but carry a smaller width:
///
///   RAX  Reg{0,64,"RAX"}   EAX Reg{0,32,"EAX"}   AX Reg{0,16,"AX"}
///   AL   Reg{0, 8,"AL"}    AH  Reg{1, 8,"AH"}
///
/// Layout (one slot = 8 bytes):
///   RAX RCX RDX RBX RSP RBP RSI RDI R8..R15  RIP  CF PF AF ZF SF OF DF
///     0   8  16  24  32  40  48  56   64-120  128 136 ...              142
///
/// Flag registers occupy one byte slot each and are 8-bit wide
/// (as defined in x86registers.def).

namespace dragon::x86 {

// ---------------------------------------------------------------------------
// Offset constants - use these if you need the raw byte offset.
// ---------------------------------------------------------------------------

inline constexpr ignil::Width k8  =  8;
inline constexpr ignil::Width k16 = 16;
inline constexpr ignil::Width k32 = 32;
inline constexpr ignil::Width k64 = 64;

inline constexpr std::uint32_t kOffRAX = 0;
inline constexpr std::uint32_t kOffRCX = 8;
inline constexpr std::uint32_t kOffRDX = 16;
inline constexpr std::uint32_t kOffRBX = 24;
inline constexpr std::uint32_t kOffRSP = 32;
inline constexpr std::uint32_t kOffRBP = 40;
inline constexpr std::uint32_t kOffRSI = 48;
inline constexpr std::uint32_t kOffRDI = 56;
inline constexpr std::uint32_t kOffR8  = 64;
inline constexpr std::uint32_t kOffR9  = 72;
inline constexpr std::uint32_t kOffR10 = 80;
inline constexpr std::uint32_t kOffR11 = 88;
inline constexpr std::uint32_t kOffR12 = 96;
inline constexpr std::uint32_t kOffR13 = 104;
inline constexpr std::uint32_t kOffR14 = 112;
inline constexpr std::uint32_t kOffR15 = 120;
inline constexpr std::uint32_t kOffRIP = 128;

inline constexpr std::uint32_t kOffCF  = 136;
inline constexpr std::uint32_t kOffPF  = 137;
inline constexpr std::uint32_t kOffAF  = 138;
inline constexpr std::uint32_t kOffZF  = 139;
inline constexpr std::uint32_t kOffSF  = 140;
inline constexpr std::uint32_t kOffOF  = 141;
inline constexpr std::uint32_t kOffDF  = 142;

// Long-mode segment bases, separate from the segment selectors.
inline constexpr std::uint32_t kOffFSBASE = 272;
inline constexpr std::uint32_t kOffGSBASE = 280;
inline const ignil::Reg FSBASE{kOffFSBASE, k64, "FSBASE"};
inline const ignil::Reg GSBASE{kOffGSBASE, k64, "GSBASE"};

// ---------------------------------------------------------------------------
// 64-bit general-purpose registers
// ---------------------------------------------------------------------------

inline const ignil::Reg RAX{kOffRAX, k64, "RAX"};
inline const ignil::Reg RCX{kOffRCX, k64, "RCX"};
inline const ignil::Reg RDX{kOffRDX, k64, "RDX"};
inline const ignil::Reg RBX{kOffRBX, k64, "RBX"};
inline const ignil::Reg RSP{kOffRSP, k64, "RSP"};
inline const ignil::Reg RBP{kOffRBP, k64, "RBP"};
inline const ignil::Reg RSI{kOffRSI, k64, "RSI"};
inline const ignil::Reg RDI{kOffRDI, k64, "RDI"};
inline const ignil::Reg R8 {kOffR8,  k64, "R8"};
inline const ignil::Reg R9 {kOffR9,  k64, "R9"};
inline const ignil::Reg R10{kOffR10, k64, "R10"};
inline const ignil::Reg R11{kOffR11, k64, "R11"};
inline const ignil::Reg R12{kOffR12, k64, "R12"};
inline const ignil::Reg R13{kOffR13, k64, "R13"};
inline const ignil::Reg R14{kOffR14, k64, "R14"};
inline const ignil::Reg R15{kOffR15, k64, "R15"};
inline const ignil::Reg RIP{kOffRIP, k64, "RIP"};

// ---------------------------------------------------------------------------
// 32-bit general-purpose registers
// ---------------------------------------------------------------------------

inline const ignil::Reg EAX {kOffRAX, k32, "EAX"};
inline const ignil::Reg ECX {kOffRCX, k32, "ECX"};
inline const ignil::Reg EDX {kOffRDX, k32, "EDX"};
inline const ignil::Reg EBX {kOffRBX, k32, "EBX"};
inline const ignil::Reg ESP {kOffRSP, k32, "ESP"};
inline const ignil::Reg EBP {kOffRBP, k32, "EBP"};
inline const ignil::Reg ESI {kOffRSI, k32, "ESI"};
inline const ignil::Reg EDI {kOffRDI, k32, "EDI"};
inline const ignil::Reg R8D {kOffR8,  k32, "R8D"};
inline const ignil::Reg R9D {kOffR9,  k32, "R9D"};
inline const ignil::Reg R10D{kOffR10, k32, "R10D"};
inline const ignil::Reg R11D{kOffR11, k32, "R11D"};
inline const ignil::Reg R12D{kOffR12, k32, "R12D"};
inline const ignil::Reg R13D{kOffR13, k32, "R13D"};
inline const ignil::Reg R14D{kOffR14, k32, "R14D"};
inline const ignil::Reg R15D{kOffR15, k32, "R15D"};

// ---------------------------------------------------------------------------
// 16-bit general-purpose registers
// ---------------------------------------------------------------------------

inline const ignil::Reg AX  {kOffRAX, k16, "AX"};
inline const ignil::Reg CX  {kOffRCX, k16, "CX"};
inline const ignil::Reg DX  {kOffRDX, k16, "DX"};
inline const ignil::Reg BX  {kOffRBX, k16, "BX"};
inline const ignil::Reg SP  {kOffRSP, k16, "SP"};
inline const ignil::Reg BP  {kOffRBP, k16, "BP"};
inline const ignil::Reg SI  {kOffRSI, k16, "SI"};
inline const ignil::Reg DI  {kOffRDI, k16, "DI"};
inline const ignil::Reg R8W {kOffR8,  k16, "R8W"};
inline const ignil::Reg R9W {kOffR9,  k16, "R9W"};
inline const ignil::Reg R10W{kOffR10, k16, "R10W"};
inline const ignil::Reg R11W{kOffR11, k16, "R11W"};
inline const ignil::Reg R12W{kOffR12, k16, "R12W"};
inline const ignil::Reg R13W{kOffR13, k16, "R13W"};
inline const ignil::Reg R14W{kOffR14, k16, "R14W"};
inline const ignil::Reg R15W{kOffR15, k16, "R15W"};

// ---------------------------------------------------------------------------
// 8-bit low general-purpose registers
// ---------------------------------------------------------------------------

inline const ignil::Reg AL  {kOffRAX, k8, "AL"};
inline const ignil::Reg CL  {kOffRCX, k8, "CL"};
inline const ignil::Reg DL  {kOffRDX, k8, "DL"};
inline const ignil::Reg BL  {kOffRBX, k8, "BL"};
inline const ignil::Reg SPL {kOffRSP, k8, "SPL"};
inline const ignil::Reg BPL {kOffRBP, k8, "BPL"};
inline const ignil::Reg SIL {kOffRSI, k8, "SIL"};
inline const ignil::Reg DIL {kOffRDI, k8, "DIL"};
inline const ignil::Reg R8B {kOffR8,  k8, "R8B"};
inline const ignil::Reg R9B {kOffR9,  k8, "R9B"};
inline const ignil::Reg R10B{kOffR10, k8, "R10B"};
inline const ignil::Reg R11B{kOffR11, k8, "R11B"};
inline const ignil::Reg R12B{kOffR12, k8, "R12B"};
inline const ignil::Reg R13B{kOffR13, k8, "R13B"};
inline const ignil::Reg R14B{kOffR14, k8, "R14B"};
inline const ignil::Reg R15B{kOffR15, k8, "R15B"};

// ---------------------------------------------------------------------------
// 8-bit high registers (byte 1 of the parent 64-bit register).
// Only available for RAX, RCX, RDX, RBX - the legacy high-byte aliases.
// ---------------------------------------------------------------------------

inline const ignil::Reg AH{kOffRAX + 1, k8, "AH"};
inline const ignil::Reg CH{kOffRCX + 1, k8, "CH"};
inline const ignil::Reg DH{kOffRDX + 1, k8, "DH"};
inline const ignil::Reg BH{kOffRBX + 1, k8, "BH"};

// ---------------------------------------------------------------------------
// EFLAGS - 8-bit wide in the IGNIL register space (one byte slot each).
// ---------------------------------------------------------------------------

inline const ignil::Reg CF{kOffCF, k8, "CF"}; ///< Carry flag
inline const ignil::Reg PF{kOffPF, k8, "PF"}; ///< Parity flag
inline const ignil::Reg AF{kOffAF, k8, "AF"}; ///< Auxiliary carry flag
inline const ignil::Reg ZF{kOffZF, k8, "ZF"}; ///< Zero flag
inline const ignil::Reg SF{kOffSF, k8, "SF"}; ///< Sign flag
inline const ignil::Reg OF{kOffOF, k8, "OF"}; ///< Overflow flag
inline const ignil::Reg DF{kOffDF, k8, "DF"}; ///< Direction flag

// ---------------------------------------------------------------------------
// Register file - the maximal registers of the space above. Analyses that must
// resolve how many bytes a sub-register write really clobbers take this list;
// see ignil::RegExtent and ignil::DeadStoreOptions::registerFile.
// ---------------------------------------------------------------------------

/// XMM is represented by two 64-bit banks. The original low-half offsets and
/// the FS/GS offsets are ABI-stable; high halves live in a separate bank.
inline constexpr std::uint32_t kOffXMM0 = 143;
inline constexpr std::uint32_t kOffXMM0Hi = 288;
inline constexpr unsigned kNumXMM = 16;
inline constexpr std::uint32_t kRegisterFileBytes = kOffXMM0Hi + 8 * kNumXMM;

inline const ignil::Reg XMM0{kOffXMM0 + 0 * 8, k64, "XMM0"};
inline const ignil::Reg XMM0_HI{kOffXMM0Hi + 0 * 8, k64, "XMM0_HI"};
inline const ignil::Reg XMM1{kOffXMM0 + 1 * 8, k64, "XMM1"};
inline const ignil::Reg XMM1_HI{kOffXMM0Hi + 1 * 8, k64, "XMM1_HI"};
inline const ignil::Reg XMM2{kOffXMM0 + 2 * 8, k64, "XMM2"};
inline const ignil::Reg XMM2_HI{kOffXMM0Hi + 2 * 8, k64, "XMM2_HI"};
inline const ignil::Reg XMM3{kOffXMM0 + 3 * 8, k64, "XMM3"};
inline const ignil::Reg XMM3_HI{kOffXMM0Hi + 3 * 8, k64, "XMM3_HI"};
inline const ignil::Reg XMM4{kOffXMM0 + 4 * 8, k64, "XMM4"};
inline const ignil::Reg XMM4_HI{kOffXMM0Hi + 4 * 8, k64, "XMM4_HI"};
inline const ignil::Reg XMM5{kOffXMM0 + 5 * 8, k64, "XMM5"};
inline const ignil::Reg XMM5_HI{kOffXMM0Hi + 5 * 8, k64, "XMM5_HI"};
inline const ignil::Reg XMM6{kOffXMM0 + 6 * 8, k64, "XMM6"};
inline const ignil::Reg XMM6_HI{kOffXMM0Hi + 6 * 8, k64, "XMM6_HI"};
inline const ignil::Reg XMM7{kOffXMM0 + 7 * 8, k64, "XMM7"};
inline const ignil::Reg XMM7_HI{kOffXMM0Hi + 7 * 8, k64, "XMM7_HI"};
inline const ignil::Reg XMM8{kOffXMM0 + 8 * 8, k64, "XMM8"};
inline const ignil::Reg XMM8_HI{kOffXMM0Hi + 8 * 8, k64, "XMM8_HI"};
inline const ignil::Reg XMM9{kOffXMM0 + 9 * 8, k64, "XMM9"};
inline const ignil::Reg XMM9_HI{kOffXMM0Hi + 9 * 8, k64, "XMM9_HI"};
inline const ignil::Reg XMM10{kOffXMM0 + 10 * 8, k64, "XMM10"};
inline const ignil::Reg XMM10_HI{kOffXMM0Hi + 10 * 8, k64, "XMM10_HI"};
inline const ignil::Reg XMM11{kOffXMM0 + 11 * 8, k64, "XMM11"};
inline const ignil::Reg XMM11_HI{kOffXMM0Hi + 11 * 8, k64, "XMM11_HI"};
inline const ignil::Reg XMM12{kOffXMM0 + 12 * 8, k64, "XMM12"};
inline const ignil::Reg XMM12_HI{kOffXMM0Hi + 12 * 8, k64, "XMM12_HI"};
inline const ignil::Reg XMM13{kOffXMM0 + 13 * 8, k64, "XMM13"};
inline const ignil::Reg XMM13_HI{kOffXMM0Hi + 13 * 8, k64, "XMM13_HI"};
inline const ignil::Reg XMM14{kOffXMM0 + 14 * 8, k64, "XMM14"};
inline const ignil::Reg XMM14_HI{kOffXMM0Hi + 14 * 8, k64, "XMM14_HI"};
inline const ignil::Reg XMM15{kOffXMM0 + 15 * 8, k64, "XMM15"};
inline const ignil::Reg XMM15_HI{kOffXMM0Hi + 15 * 8, k64, "XMM15_HI"};

/// Each XMM half has its own eight-byte extent, since the banks are disjoint.
/// No 32-bit register writes are used for packed lanes: lane operations use
/// temporaries, avoiding the x86 GPR zero-extension rule for register writes.
[[nodiscard]] inline std::vector<ignil::RegExtent> registerFile() {
  std::vector<ignil::RegExtent> file;
  file.reserve(17 + 7 + 2 * kNumXMM + 2);
  for (std::uint32_t off = kOffRAX; off <= kOffRIP; off += 8)
    file.push_back({off, 8}); // RAX..R15, RIP
  for (std::uint32_t off = kOffCF; off <= kOffDF; ++off)
    file.push_back({off, 1}); // CF PF AF ZF SF OF DF
  for (unsigned i = 0; i < kNumXMM; ++i)
    file.push_back({kOffXMM0 + i * 8, 8}); // XMM0..XMM15
  file.push_back({kOffFSBASE, 8});
  file.push_back({kOffGSBASE, 8});
  for (unsigned i = 0; i < kNumXMM; ++i)
    file.push_back({kOffXMM0Hi + i * 8, 8});
  return file;
}

} // namespace dragon::x86
