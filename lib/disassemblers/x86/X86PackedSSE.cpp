#include "X86IGNILLifter.hpp"

#include <dragon/lifters/ignil/x86/x86IGNILRegs.hpp>

#include <llvm/MC/MCInst.h>

#include <algorithm>
#include <string>
#include <string_view>
#include <unordered_map>

using namespace dragon::ignil;

namespace dragon::x86 {

void X86IGNILLifter::initializePackedSSE(const llvm::MCInstrInfo &info) {
  // Resolve LLVM's internal opcode spellings once, never in the hot path.
  std::unordered_map<std::string, PackedForm> names;
  auto put = [&](std::string name, PackedKind kind, bool mem = false,
                 bool store = false) {
    names.emplace(name, PackedForm{kind, mem, store});
  };
  for (const auto *stem:
       {"MOVAPS", "MOVUPS", "MOVAPD", "MOVUPD", "MOVDQA", "MOVDQU"}) {
    put(std::string(stem) + "rr", PackedKind::Move);
    put(std::string(stem) + "rm", PackedKind::Move, true);
    put(std::string(stem) + "mr", PackedKind::Move, true, true);
  }
  for (auto [stem, kind]: {std::pair{"PXOR", PackedKind::Xor},
                           {"XORPS", PackedKind::Xor},
                           {"XORPD", PackedKind::Xor},
                           {"PAND", PackedKind::And},
                           {"ANDPS", PackedKind::And},
                           {"ANDPD", PackedKind::And},
                           {"POR", PackedKind::Or},
                           {"ORPS", PackedKind::Or},
                           {"ORPD", PackedKind::Or},
                           {"PANDN", PackedKind::AndNot},
                           {"ANDNPS", PackedKind::AndNot},
                           {"ANDNPD", PackedKind::AndNot},
                           {"PADDD", PackedKind::Add32},
                           {"PSUBD", PackedKind::Sub32},
                           {"PMULLD", PackedKind::Mul32},
                           {"PUNPCKLDQ", PackedKind::UnpackLow32},
                           {"PUNPCKHDQ", PackedKind::UnpackHigh32},
                           {"PUNPCKLQDQ", PackedKind::UnpackLow64},
                           {"PUNPCKHQDQ", PackedKind::UnpackHigh64}}) {
    put(std::string(stem) + "rr", kind);
    put(std::string(stem) + "rm", kind, true);
  }
  put("MOVDI2PDIrr", PackedKind::MoveToXMM32);
  put("MOVDI2PDIrm", PackedKind::MoveToXMM32, true);
  put("MOVPDI2DIrr", PackedKind::MoveFromXMM32);
  put("MOVPDI2DImr", PackedKind::MoveFromXMM32, true, true);
  put("MOV64toPQIrr", PackedKind::MoveToXMM64);
  put("MOVQI2PQIrm", PackedKind::MoveToXMM64, true);
  put("MOVZPQILo2PQIrr", PackedKind::MoveToXMM64);
  put("MOVPQIto64rr", PackedKind::MoveFromXMM64);
  put("MOVPQI2QImr", PackedKind::MoveFromXMM64, true, true);
  put("PSHUFDri", PackedKind::Shuffle32);
  put("PSHUFDmi", PackedKind::Shuffle32, true);
  put("PSRLDQri", PackedKind::ShiftRightBytes);
  put("PSLLDQri", PackedKind::ShiftLeftBytes);
  put("PSRLDri", PackedKind::ShiftRight32);
  put("PSLLDri", PackedKind::ShiftLeft32);
  put("PSRADri", PackedKind::ShiftArith32);
  for (unsigned i = 0; i < info.getNumOpcodes(); ++i) {
    if (auto it = names.find(std::string(info.getName(i))); it != names.end())
      packedForms_.emplace(i, it->second);
  }
}

std::optional<std::array<Reg, 2>>
X86IGNILLifter::xmmParts(unsigned llvmReg) const {
  auto low = toReg(llvmReg);
  if (!low || low->width != 64 || low->offset < kOffXMM0 ||
      low->offset >= kOffXMM0 + 8 * kNumXMM || (low->offset - kOffXMM0) % 8)
    return std::nullopt;
  const auto index = (low->offset - kOffXMM0) / 8;
  return std::array<Reg, 2>{*low, Reg{kOffXMM0Hi + 8 * index, 64,
                                      "XMM" + std::to_string(index) + "_HI"}};
}

void X86IGNILLifter::liftPackedSSE(const llvm::MCInst &mc, PackedForm form,
                                   std::uint64_t addr, Block &out,
                                   std::uint32_t &tmp) const {
  using K = PackedKind;
  using Pair = std::array<Value, 2>;
  using Lanes = std::array<Value, 4>;
  auto emit = [&](Opcode op, Width width, std::initializer_list<Value> src) {
    Temp result = newTemp(tmp, width);
    out.append({op, result, src, addr});
    return result;
  };
  auto copy = [&](Value value, Width width = 64) {
    return emit(Opcode::COPY, width, {value});
  };
  auto snapshot = [&](unsigned operand) -> Pair {
    const auto parts = xmmParts(mc.getOperand(operand).getReg()).value();
    return {copy(parts[0]), copy(parts[1])};
  };
  auto load = [&](unsigned operand, Width width) {
    const auto ptr = emitAddress(mc, operand, 64, addr, out, tmp);
    return emit(Opcode::LOAD, width, {ptr});
  };
  auto load128 = [&](unsigned operand) -> Pair {
    const auto ptr = emitAddress(mc, operand, 64, addr, out, tmp);
    const auto next = emit(Opcode::ADD, 64, {ptr, Const{8, 64}});
    return {emit(Opcode::LOAD, 64, {ptr}), emit(Opcode::LOAD, 64, {next})};
  };
  auto write = [&](Pair value) {
    const auto parts = xmmParts(mc.getOperand(0).getReg()).value();
    out.append({Opcode::COPY, parts[0], {value[0]}, addr});
    out.append({Opcode::COPY, parts[1], {value[1]}, addr});
  };
  auto lanes = [&](Pair value) -> Lanes {
    return {emit(Opcode::TRUNC, 32, {value[0]}),
            emit(Opcode::TRUNC, 32,
                 {emit(Opcode::SHR, 64, {value[0], Const{32, 64}})}),
            emit(Opcode::TRUNC, 32, {value[1]}),
            emit(Opcode::TRUNC, 32,
                 {emit(Opcode::SHR, 64, {value[1], Const{32, 64}})})};
  };
  auto pack = [&](Lanes value) -> Pair {
    auto half = [&](unsigned i) {
      const auto lo = emit(Opcode::ZEXT, 64, {value[i]});
      const auto hi = emit(Opcode::ZEXT, 64, {value[i + 1]});
      return emit(Opcode::OR, 64,
                  {lo, emit(Opcode::SHL, 64, {hi, Const{32, 64}})});
    };
    return {half(0), half(2)};
  };
  const Value zero = Const{0, 64};
  const auto kind = form.kind;
  if (kind == K::MoveToXMM32 || kind == K::MoveToXMM64) {
    const Width width = kind == K::MoveToXMM32 ? 32 : 64;
    Value value;
    if (form.memory)
      value = load(1, width);
    else
      value = copy(toReg(mc.getOperand(1).getReg()).value(), width);
    write({width == 32 ? Value{emit(Opcode::ZEXT, 64, {value})} : value, zero});
    return;
  }
  if (kind == K::MoveFromXMM32 || kind == K::MoveFromXMM64) {
    const Width width = kind == K::MoveFromXMM32 ? 32 : 64;
    const auto src = snapshot(form.store ? 5 : 1);
    const Value value =
            width == 32 ? Value{emit(Opcode::TRUNC, 32, {src[0]})} : src[0];
    if (form.store) {
      const auto ptr = emitAddress(mc, 0, 64, addr, out, tmp);
      out.append({Opcode::STORE, {}, {ptr, value}, addr});
    } else {
      out.append({Opcode::COPY,
                  toReg(mc.getOperand(0).getReg()).value(),
                  {value},
                  addr});
    }
    return;
  }
  if (kind == K::Move) {
    if (form.store) {
      // Snapshot both halves before writing memory (including overlapping use).
      const auto src = snapshot(5);
      const auto ptr = emitAddress(mc, 0, 64, addr, out, tmp);
      const auto next = emit(Opcode::ADD, 64, {ptr, Const{8, 64}});
      out.append({Opcode::STORE, {}, {ptr, src[0]}, addr});
      out.append({Opcode::STORE, {}, {next, src[1]}, addr});
    } else {
      write(form.memory ? load128(1) : snapshot(1));
    }
    return;
  }
  if (kind == K::Shuffle32) {
    const auto src = lanes(form.memory ? load128(1) : snapshot(1));
    const auto imm =
            static_cast<unsigned>(mc.getOperand(form.memory ? 6 : 2).getImm());
    write(pack({src[imm & 3], src[(imm >> 2) & 3], src[(imm >> 4) & 3],
                src[(imm >> 6) & 3]}));
    return;
  }
  const auto lhs = snapshot(1);
  if (kind == K::ShiftLeftBytes || kind == K::ShiftRightBytes) {
    // Unlike scalar shifts, byte shifts saturate at 16, never mask the count.
    const auto count = static_cast<unsigned>(mc.getOperand(2).getImm()) & 0xff;
    const bool left = kind == K::ShiftLeftBytes;
    if (count == 0) {
      write(lhs);
    } else if (count >= 16) {
      write({zero, zero});
    } else {
      const auto bits = count * 8;
      Pair result{zero, zero};
      if (bits >= 64) {
        result[left ? 1 : 0] = emit(left ? Opcode::SHL : Opcode::SHR, 64,
                                    {lhs[left ? 0 : 1], Const{bits - 64, 64}});
      } else if (left) {
        result[0] = emit(Opcode::SHL, 64, {lhs[0], Const{bits, 64}});
        result[1] =
                emit(Opcode::OR, 64,
                     {emit(Opcode::SHL, 64, {lhs[1], Const{bits, 64}}),
                      emit(Opcode::SHR, 64, {lhs[0], Const{64 - bits, 64}})});
      } else {
        result[0] =
                emit(Opcode::OR, 64,
                     {emit(Opcode::SHR, 64, {lhs[0], Const{bits, 64}}),
                      emit(Opcode::SHL, 64, {lhs[1], Const{64 - bits, 64}})});
        result[1] = emit(Opcode::SHR, 64, {lhs[1], Const{bits, 64}});
      }
      write(result);
    }
    return;
  }
  if (kind == K::ShiftRight32 || kind == K::ShiftLeft32 ||
      kind == K::ShiftArith32) {
    const auto count = static_cast<unsigned>(mc.getOperand(2).getImm()) & 0xff;
    auto result = lanes(lhs);
    const auto op = kind == K::ShiftRight32  ? Opcode::SHR
                    : kind == K::ShiftLeft32 ? Opcode::SHL
                                             : Opcode::SAR;
    for (auto &lane: result)
      lane = count >= 32 && kind != K::ShiftArith32
                     ? Value{Const{0, 32}}
                     : Value{emit(op, 32,
                                  {lane, Const{std::min(count, 31u), 32}})};
    write(pack(result));
    return;
  }
  // All binary forms have dst,tied-lhs,rhs (or five memory operands as rhs).
  // No destination writes have occurred, so dst==rhs and all in-place forms
  // have precisely the same meaning as separate-register operations.
  const auto rhs = form.memory ? load128(2) : snapshot(2);
  if (kind == K::Xor || kind == K::And || kind == K::Or || kind == K::AndNot) {
    Pair result;
    for (unsigned i = 0; i < 2; ++i) {
      const Value a = kind == K::AndNot ? Value{emit(Opcode::NOT, 64, {lhs[i]})}
                                        : lhs[i];
      const auto op = kind == K::Xor  ? Opcode::XOR
                      : kind == K::Or ? Opcode::OR
                                      : Opcode::AND;
      result[i] = emit(op, 64, {a, rhs[i]});
    }
    write(result);
  } else if (kind == K::UnpackLow64 || kind == K::UnpackHigh64) {
    const auto i = kind == K::UnpackHigh64 ? 1 : 0;
    write({lhs[i], rhs[i]});
  } else {
    const auto a = lanes(lhs), b = lanes(rhs);
    Lanes result;
    if (kind == K::UnpackLow32 || kind == K::UnpackHigh32) {
      const auto i = kind == K::UnpackHigh32 ? 2 : 0;
      result = {a[i], b[i], a[i + 1], b[i + 1]};
    } else {
      const auto op = kind == K::Add32   ? Opcode::ADD
                      : kind == K::Sub32 ? Opcode::SUB
                                         : Opcode::MUL;
      for (unsigned i = 0; i < 4; ++i)
        result[i] = emit(op, 32, {a[i], b[i]});
    }
    write(pack(result));
  }
}

} // namespace dragon::x86
