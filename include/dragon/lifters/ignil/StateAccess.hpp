#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace dragon::ignil {

/// A watched physical state range, not an architectural register write.
struct StateRange {
  bool memory;
  std::uint64_t key;
  std::uint64_t bytes;
};

/// Conservative byte liveness along one resolved, ordered execution.
/// It observes physical aliases/overlaps, not expression-variable names. Only
/// supplied ranges are watched; an empty list watches all accessed bytes.
/// It neither changes nor generalizes the state. A capacity limit fails closed.
class StateAccessTrace {
  public:
  enum Flag : unsigned {
    LiveIn = 1,
    Read = 2,
    Written = 4,
    ControlRead = 8,
    EntryRead = 16,
    EntryControlRead = 32,
    Preserved = 64
  };
  struct Byte {
    bool memory;
    std::uint64_t key;
    unsigned flags;
  };
  explicit StateAccessTrace(const std::vector<StateRange> &ranges) :
      all_(ranges.empty()) {
    for (const auto &r: ranges) {
      for (std::uint64_t i = 0; i < r.bytes && !overflow_; ++i)
        insert(r.memory ? memory_ : registers_, r.key + i);
      if (overflow_)
        break;
    }
  }
  void observe(bool memory, std::uint64_t base, std::uint64_t bytes, bool write,
               unsigned readFlag = Read) {
    if (!active_ || !cacheable_)
      return;
    auto &watched = memory ? memory_ : registers_;
    if (all_)
      for (std::uint64_t i = 0; i < bytes; ++i)
        insert(watched, base + i);
    auto visit = [&](std::uint64_t begin, std::uint64_t end) {
      for (auto it = watched.lower_bound(begin);
           it != watched.end() && it->first < end; ++it) {
        auto &flags = it->second;
        if (write)
          flags |= Written;
        else {
          if (!(flags & Written))
            flags |= LiveIn;
          flags |= readFlag;
        }
      }
    };
    const auto end = base + bytes;
    if (end < base) {
      // Widths are small, so wraparound can also be handled byte by byte.
      for (std::uint64_t i = 0; i < bytes; ++i) {
        if (auto it = watched.find(base + i); it != watched.end()) {
          auto &flags = it->second;
          if (write)
            flags |= Written;
          else {
            if (!(flags & Written))
              flags |= LiveIn;
            flags |= readFlag;
          }
        }
      }
    } else
      visit(base, end);
  }
  bool complete() const { return !overflow_; }
  bool cacheable() const { return cacheable_; }
  bool hasExits() const { return definiteWrites_.has_value(); }
  void invalidateSummary() { cacheable_ = false; }
  // Called at each matched invocation return. A maybe-written byte retains
  // its entry value on some path, even if no instruction explicitly read it.
  void recordExit(const std::set<std::pair<bool, std::uint64_t>> &written) {
    if (!cacheable_ || overflow_)
      return;
    if (!definiteWrites_)
      definiteWrites_ = written;
    else
      std::erase_if(*definiteWrites_,
                    [&](const auto &byte) { return !written.contains(byte); });
  }
  /// Disable every snapshot sharing this observer before reading diagnostics.
  std::vector<Byte> finish() {
    active_ = false;
    std::vector<Byte> result;
    for (const auto &[key, flags]: registers_)
      result.push_back({false, key, flags | preserved(false, key, flags)});
    for (const auto &[key, flags]: memory_)
      result.push_back({true, key, flags | preserved(true, key, flags)});
    return result;
  }

  private:
  unsigned preserved(bool memory, std::uint64_t key, unsigned flags) const {
    return definiteWrites_ && (flags & Written) &&
                           !definiteWrites_->contains({memory, key})
                   ? Preserved
                   : 0;
  }
  std::optional<std::set<std::pair<bool, std::uint64_t>>> definiteWrites_;
  void insert(std::map<std::uint64_t, unsigned> &map, std::uint64_t key) {
    if (map.contains(key))
      return;
    if (registers_.size() + memory_.size() >= (1u << 20)) {
      overflow_ = true;
      return;
    }
    map.emplace(key, 0);
  }
  bool active_ = true, all_ = false, overflow_ = false, cacheable_ = true;
  std::map<std::uint64_t, unsigned> registers_, memory_;
};

} // namespace dragon::ignil
