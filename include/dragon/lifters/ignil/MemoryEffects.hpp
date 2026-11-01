#pragma once

#include <cstdint>
#include <vector>
#include <z3++.h>

namespace dragon::ignil {

/// An actual executed memory operation, not a final concrete-address diff.
/// For a load, value is a unique result token constrained by the current array.
struct MemoryEffect {
  bool isStore;
  std::uint64_t opAddress;
  unsigned width;
  z3::expr address;
  z3::expr value;
};

/// Opt-in, little-endian, flat x86-64 memory semantics for a resolved path.
/// ALL IGNIL LOAD/STORE operations share ONE BV64 -> BV8 array. No p != q,
/// object-separation or capture-byte assumptions are introduced. Copying this
/// object snapshots both the array version and ordered event history.
/// Ordinary captured/concrete SymbolicState memory is a separate mode; it is
/// deliberately not used to specialize this initially unconstrained memory.
class MemoryEffects {
  public:
  explicit MemoryEffects(z3::context &ctx);
  z3::expr load(const z3::expr &address, unsigned width, std::uint64_t pc);
  void store(const z3::expr &address, const z3::expr &value, std::uint64_t pc);
  [[nodiscard]] z3::expr read(const z3::expr &address, unsigned width) const;
  void invalidate() { valid_ = false; }
  [[nodiscard]] bool valid() const { return valid_; }
  [[nodiscard]] const z3::expr &initial() const { return initial_; }
  [[nodiscard]] const z3::expr &memory() const { return memory_; }
  [[nodiscard]] const std::vector<MemoryEffect> &events() const {
    return events_;
  }
  [[nodiscard]] const std::vector<z3::expr> &constraints() const {
    return constraints_;
  }

  private:
  bool valid_ = true;
  z3::expr initial_;
  z3::expr memory_;
  std::vector<MemoryEffect> events_;
  std::vector<z3::expr> constraints_;
};
} // namespace dragon::ignil
