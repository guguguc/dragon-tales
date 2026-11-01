#include <dragon/lifters/ignil/IGNIL.hpp>

#include "utils/Utils.hpp"

#include <format>


#define OP_NAME(OP) #OP,
static constexpr std::string_view kNames[] = {
#include "IGNIL_OPS.def"

};
#undef OP_NAME

dragon::ignil::Width dragon::ignil::widthOf(const Value &v) {
  return std::visit([](const auto &val) { return val.width; }, v);
}

dragon::ignil::Block::Block(std::uint64_t startAddress) :
    startAddress_(startAddress) {}

void dragon::ignil::Block::append(Op op) { ops_.push_back(std::move(op)); }

void dragon::ignil::Block::noteUnlifted(std::uint64_t address) {
  if (unlifted_.empty() || unlifted_.back() != address)
    unlifted_.push_back(address);
}

const std::vector<std::uint64_t> &dragon::ignil::Block::unlifted() const {
  return unlifted_;
}

const std::vector<dragon::ignil::Op> &dragon::ignil::Block::ops() const {
  return ops_;
}
std::uint64_t dragon::ignil::Block::startAddress() const {
  return startAddress_;
}
bool dragon::ignil::Block::empty() const { return ops_.empty(); }
size_t dragon::ignil::Block::size() const { return ops_.size(); }
std::vector<dragon::ignil::Op>::const_iterator
dragon::ignil::Block::begin() const {
  return ops_.begin();
}
std::vector<dragon::ignil::Op>::const_iterator
dragon::ignil::Block::end() const {
  return ops_.end();
}

std::string_view dragon::ignil::opcodeName(Opcode op) {
  auto i = static_cast<std::size_t>(op);
  return i < std::size(kNames) ? kNames[i] : "?";
}

std::string dragon::ignil::toString(const Value &v) {
  return std::visit(
          utils::overloaded{
                  [](const Const &c) {
                    return std::format("0x{:x}:i{}", c.value, c.width);
                  },
                  [](const Reg &r) {
                    if (!r.name.empty())
                      return std::format("{}:i{}", r.name, r.width);
                    return std::format("reg[{}]:i{}", r.offset, r.width);
                  },
                  [](const Temp &t) {
                    return std::format("t{}:i{}", t.id, t.width);
                  }},
          v);
}

std::string_view dragon::ignil::opaqueKindName(OpaqueKind kind) {
  switch (kind) {
    case OpaqueKind::CPUID: return "cpuid";
    case OpaqueKind::RDTSC: return "rdtsc";
    case OpaqueKind::RDTSCP: return "rdtscp";
  }
  return "opaque";
}

bool dragon::ignil::opaqueIsPure(OpaqueKind kind) {
  switch (kind) {
    case OpaqueKind::CPUID: return true;
    // Each execution is its own reading of the clock.
    case OpaqueKind::RDTSC:
    case OpaqueKind::RDTSCP: return false;
  }
  return false;
}

unsigned dragon::ignil::opaqueResultCount(OpaqueKind kind) {
  switch (kind) {
    case OpaqueKind::CPUID: return 4;
    case OpaqueKind::RDTSC: return 2;
    case OpaqueKind::RDTSCP: return 3;
  }
  return 0;
}

std::string dragon::ignil::toString(const Op &op) {
  std::string s;
  if (op.dst)
    s += toString(*op.dst) + " = ";
  s += std::string(opcodeName(op.opcode));
  if (op.opcode == Opcode::OPAQUE)
    s += std::format("<{}:{}>", opaqueKindName(opaqueKindOf(op.aux)),
                     opaqueIndexOf(op.aux));
  s += "(";
  for (std::size_t i = 0; i < op.srcs.size(); ++i) {
    if (i)
      s += ", ";
    s += toString(op.srcs[i]);
  }
  s += ")";
  if (op.address)
    s += std::format("  ; @0x{:x}", op.address);
  return s;
}

std::string dragon::ignil::toString(const Block &block) {
  std::string s = std::format("IGNILBlock @ 0x{:x}\n", block.startAddress());
  for (const auto &op: block)
    s += "  " + toString(op) + "\n";
  return s;
}
