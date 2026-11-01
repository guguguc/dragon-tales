#include <dragon/lifters/ignil/SymbolicExecutor.hpp>
#include "SymbolicFold.hpp"

#include <algorithm>
#include <chrono>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>
#include <utility>

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <intrin.h>
#elif defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#include <x86intrin.h>
#endif

namespace dragon::ignil {

namespace {

// Execute only a local timing instruction, never any target machine code.
std::optional<HostTimestamp> readHostTimestamp(const Op &op, OpaqueKind kind) {
#if (defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))) ||            \
        defined(__x86_64__) || defined(__i386__)
  static const auto supported = [] {
    std::pair<bool, bool> result{false, false};
#if defined(_MSC_VER)
    int regs[4]{};
    __cpuid(regs, 0);
    if (regs[0] >= 1) {
      __cpuid(regs, 1);
      result.first = (static_cast<unsigned>(regs[3]) & (1u << 4)) != 0;
    }
    __cpuid(regs, static_cast<int>(0x80000000u));
    if (static_cast<unsigned>(regs[0]) >= 0x80000001u) {
      __cpuid(regs, static_cast<int>(0x80000001u));
      result.second = (static_cast<unsigned>(regs[3]) & (1u << 27)) != 0;
    }
#else
    unsigned a, b, c, d;
    if (__get_cpuid(1, &a, &b, &c, &d))
      result.first = (d & (1u << 4)) != 0;
    if (__get_cpuid(0x80000001u, &a, &b, &c, &d))
      result.second = (d & (1u << 27)) != 0;
#endif
    return result;
  }();
  if (kind == OpaqueKind::RDTSC && supported.first)
    return HostTimestamp{op.address, kind, __rdtsc(), 0};
  if (kind == OpaqueKind::RDTSCP && supported.second) {
    unsigned aux = 0;
    const auto tsc = __rdtscp(&aux);
    return HostTimestamp{op.address, kind, tsc, aux};
  }
#endif
  return std::nullopt;
}

// ---------------------------------------------------------------------------
// Small Z3 helpers
// ---------------------------------------------------------------------------

/// Bitvector literal. The explicit uint64_t cast matters: z3::context::bv_val
/// is overloaded on int/unsigned/int64_t/uint64_t, and anything else (an
/// `unsigned long long`, say) converts to several of them equally well and is
/// ambiguous.
z3::expr bvVal(z3::context &ctx, std::uint64_t value, Width width) {
  return ctx.bv_val(static_cast<std::uint64_t>(value), width);
}

/// Mask a host value down to `width` bits.
std::uint64_t maskTo(std::uint64_t v, Width width) {
  if (width >= 64)
    return v;
  return v & ((std::uint64_t{1} << width) - 1);
}

Width bvWidth(const z3::expr &e) {
  return static_cast<Width>(e.get_sort().bv_size());
}

/// Zero-extend or truncate `e` to exactly `width` bits.
z3::expr zeroCoerce(const z3::expr &e, Width width) {
  const Width cur = bvWidth(e);
  if (cur == width)
    return e;
  if (cur > width)
    return fold::slice(e, width - 1, 0);
  return fold::local(z3::zext(e, width - cur));
}

/// Sign-extend or truncate `e` to exactly `width` bits.
z3::expr signCoerce(const z3::expr &e, Width width) {
  const Width cur = bvWidth(e);
  if (cur == width)
    return e;
  if (cur > width)
    return fold::slice(e, width - 1, 0);
  return z3::sext(e, width - cur);
}

/// True for opcodes that read their operands as signed, and so must be
/// sign-extended rather than zero-extended when widened to a common width.
bool isSignedOp(Opcode op) {
  switch (op) {
    case Opcode::SDIV:
    case Opcode::SMOD:
    case Opcode::SLT:
    case Opcode::SLE:
    case Opcode::SGT:
    case Opcode::SGE:
      return true;
    default:
      return false;
  }
}

bool isComparison(Opcode op) {
  switch (op) {
    case Opcode::EQ:
    case Opcode::NEQ:
    case Opcode::ULT:
    case Opcode::ULE:
    case Opcode::UGT:
    case Opcode::UGE:
    case Opcode::SLT:
    case Opcode::SLE:
    case Opcode::SGT:
    case Opcode::SGE:
      return true;
    default:
      return false;
  }
}

/// IEEE754 binary64, the only float format IGNIL models.
z3::sort float64Sort(z3::context &ctx) { return ctx.fpa_sort(11, 53); }

std::string hex(std::uint64_t v) {
  std::ostringstream os;
  os << "0x" << std::hex << v;
  return os.str();
}

/// Name of the free variable standing in for a never-written register byte.
std::string lazyRegName(std::uint64_t offset) {
  return "reg[" + std::to_string(offset) + "]";
}

/// Name of the free variable standing in for a never-written memory byte.
std::string lazyMemName(std::uint64_t addr) { return "mem[" + hex(addr) + "]"; }

/// Bytes needed to hold `width` bits.
std::uint64_t byteCount(Width width) { return (width + 7u) / 8u; }

} // namespace

// ---------------------------------------------------------------------------
// Solution
// ---------------------------------------------------------------------------

std::optional<std::uint64_t> Solution::value(std::string_view symbol) const {
  auto it = values_.find(std::string(symbol));
  if (it == values_.end())
    return std::nullopt;
  return it->second;
}

std::vector<std::uint8_t> Solution::bytes(std::string_view region) const {
  const std::string name(region);
  auto it = regionSizes_.find(name);
  if (it == regionSizes_.end())
    return {};

  std::vector<std::uint8_t> out;
  out.reserve(it->second);
  for (std::uint64_t i = 0; i < it->second; ++i) {
    auto v = value(name + "[" + std::to_string(i) + "]");
    out.push_back(static_cast<std::uint8_t>(v.value_or(0) & 0xFF));
  }
  return out;
}

// ---------------------------------------------------------------------------
// SymbolicState
// ---------------------------------------------------------------------------

SymbolicState::SymbolicState(z3::context &ctx, SymbolicOptions opts) :
    ctx_(&ctx), opts_(std::move(opts)) {}

z3::expr SymbolicState::symbol(std::string_view name, Width width) const {
  std::string key(name);
  auto it = symbols_.find(key);
  if (it != symbols_.end())
    return it->second;
  z3::expr s = ctx_->bv_const(key.c_str(), width);
  symbols_.emplace(key, s);
  return s;
}

z3::expr SymbolicState::readByte(const ByteStore &store, std::uint64_t key,
                                 std::string_view kind) const {
  auto it = store.find(key);
  if (it != store.end()) {
    const StoredByte &b = it->second;
    return fold::slice(b.source, b.index * 8 + 7, b.index * 8);
  }
  if (kind == "mem")
    if (auto concrete = imageByte(key))
      return bvVal(*ctx_, *concrete, 8);
  if (!opts_.symbolizeUnmappedReads)
    return bvVal(*ctx_, 0, 8);
  // Deterministic name, so two reads of the same never-written location agree
  // without having to write the placeholder back into the store (which would
  // make isRegisterDefined/isMemoryDefined lie).
  return symbol(kind == "reg" ? lazyRegName(key) : lazyMemName(key), 8);
}

std::optional<std::uint8_t>
SymbolicState::imageByte(std::uint64_t addr) const {
  for (auto it = images_.rbegin(); it != images_.rend(); ++it)
    if (addr >= it->base && addr - it->base < it->bytes->size())
      return (*it->bytes)[addr - it->base];
  return std::nullopt;
}

std::optional<std::uint8_t>
SymbolicState::concreteByte(const ByteStore &store, std::uint64_t key,
                            bool images) const {
  if (auto it = store.find(key); it != store.end()) {
    const StoredByte &b = it->second;
    // get_numeral_uint64 only reads 64 bits; a wider literal (a vector
    // register) goes through the general path instead.
    if (!b.source.is_numeral() || bvWidth(b.source) > 64)
      return std::nullopt;
    return static_cast<std::uint8_t>(
            (b.source.get_numeral_uint64() >> (b.index * 8)) & 0xFF);
  }
  return images ? imageByte(key) : std::nullopt;
}

void SymbolicState::writeBytes(ByteStore &store, std::uint64_t base,
                               const z3::expr &value, Width width) {
  const std::uint64_t n = byteCount(width);
  // A sub-byte value (a 1-bit comparison result written to a flag) is widened
  // to a whole byte first - the stores are byte-granular.
  const z3::expr v = zeroCoerce(value, static_cast<Width>(n * 8));
  for (std::uint64_t i = 0; i < n; ++i)
    store.insert_or_assign(base + i,
                           StoredByte{v, static_cast<unsigned>(i)});
}

z3::expr SymbolicState::readBytes(const ByteStore &store, std::uint64_t base,
                                  Width width, std::string_view kind) const {
  const std::uint64_t n = byteCount(width);

  // Preserve a whole value OR any contiguous subrange of it. Byte indices
  // are provenance, not independent symbolic bytes; partial reads must not
  // destroy the original word-level expression.
  if (auto first = store.find(base); first != store.end()) {
    const z3::expr &source = first->second.source;
    const unsigned offset = first->second.index;
    bool intact = (offset + n) * 8 <= bvWidth(source);
    for (std::uint64_t i = 1; intact && i < n; ++i) {
      auto it = store.find(base + i);
      intact = it != store.end() && it->second.index == offset + i &&
               it->second.source.id() == source.id();
    }
    if (intact)
      return fold::slice(source, offset * 8 + width - 1, offset * 8);
  }

  // Second fast path: every byte is concrete, so the value is a literal and
  // there is no need to build a concat of extracts only for simplify() to
  // fold it straight back. This is what keeps a concrete run - image bytes,
  // a concrete stack - from paying for Z3 terms it never needed.
  if (n <= 8) {
    const bool images = kind == "mem";
    std::uint64_t literal = 0;
    bool concrete = true;
    for (std::uint64_t i = 0; concrete && i < n; ++i) {
      if (auto b = concreteByte(store, base + i, images))
        literal |= static_cast<std::uint64_t>(*b) << (i * 8);
      else
        concrete = false;
    }
    if (concrete)
      return bvVal(*ctx_, maskTo(literal, width), width);
  }

  // Little-endian: byte `base` is the least significant, so it ends up on the
  // right of the concatenation.
  z3::expr acc = readByte(store, base, kind);
  for (std::uint64_t i = 1; i < n; ++i)
    acc = fold::concat(readByte(store, base + i, kind), acc);
  return zeroCoerce(acc, width);
}

z3::expr SymbolicState::symbolizeRange(bool memory, std::uint64_t key,
                                       Width width, std::string_view name) {
  invalidateCallTraces();
  if (!width || width % 8 || name.empty())
    throw std::invalid_argument(
            "state range binding requires a name and whole bytes");
  auto value = symbol(name, width);
  if (accessTrace_)
    accessTrace_->observe(memory, key, byteCount(width), true);
  writeBytes(memory ? memBytes_ : regBytes_, key, value, width);
  return value;
}

std::shared_ptr<StateAccessTrace> SymbolicState::beginCallTrace() {
  auto trace = std::make_shared<StateAccessTrace>(std::vector<StateRange>{});
  callTraces_.push_back({trace, {}});
  return trace;
}
void SymbolicState::detachCallTrace(
        const std::shared_ptr<StateAccessTrace> &trace) {
  for (const auto &item: callTraces_)
    if (item.unionTrace == trace)
      trace->recordExit(item.written);
  std::erase_if(callTraces_,
                [&](const auto &item) { return item.unionTrace == trace; });
}
void SymbolicState::invalidateCallTraces() {
  for (const auto &trace: callTraces_)
    trace.unionTrace->invalidateSummary();
}
void SymbolicState::observeCallAccess(bool memory, std::uint64_t key,
                                      std::uint64_t bytes, bool write,
                                      bool control) const {
  for (auto &trace: callTraces_) {
    if (!trace.unionTrace->cacheable() || !trace.unionTrace->complete())
      continue;
    for (std::uint64_t i = 0; i < bytes; ++i) {
      const auto byte = std::pair{memory, key + i};
      auto flags =
              control ? StateAccessTrace::ControlRead : StateAccessTrace::Read;
      if (write)
        trace.written.insert(byte);
      else if (!trace.written.contains(byte))
        flags = static_cast<StateAccessTrace::Flag>(
                flags | (control ? StateAccessTrace::EntryControlRead
                                 : StateAccessTrace::EntryRead));
      trace.unionTrace->observe(memory, key + i, 1, write, flags);
    }
  }
}
z3::expr SymbolicState::readRange(const StateRange &range) const {
  return readBytes(range.memory ? memBytes_ : regBytes_, range.key,
                   static_cast<Width>(range.bytes * 8),
                   range.memory ? "mem" : "reg");
}
void SymbolicState::writeRange(const StateRange &range, const z3::expr &value) {
  writeBytes(range.memory ? memBytes_ : regBytes_, range.key, value,
             static_cast<Width>(range.bytes * 8));
}
z3::expr SymbolicState::readControlMemory(std::uint64_t addr,
                                          Width width) const {
  if (accessTrace_)
    accessTrace_->observe(true, addr, byteCount(width), false);
  observeCallAccess(true, addr, byteCount(width), false, true);
  return readBytes(memBytes_, addr, width, "mem");
}

// -- diffing ----------------------------------------------------------------

std::vector<SymbolicState::Delta>
SymbolicState::diff(const SymbolicState &before) const {
  if (memoryEffects_ || before.memoryEffects_)
    throw std::invalid_argument("use ordered memory effects and array "
                                "versions, not concrete memory diff");
  std::vector<Delta> out;

  // Widest run reported as one value. Width is a uint8_t, so a run can never
  // describe more than 255 bits; 16 bytes covers every register and vector
  // write dragon models today, and anything wider falls back to byte runs.
  constexpr std::uint64_t kMaxRunBytes = 16;

  auto scan = [&](const ByteStore &now, const ByteStore &was, Delta::Kind kind,
                  std::string_view readKind) {
    // Keys whose stored byte changed, in address order (ByteStore is ordered).
    // Z3 hash-conses its AST, so equal ids mean the same expression; a byte is
    // unchanged when it is the same slice of the same written value.
    std::vector<std::uint64_t> changed;
    for (const auto &[key, byte] : now) {
      const auto old = was.find(key);
      if (old == was.end() || old->second.index != byte.index ||
          old->second.source.id() != byte.source.id())
        changed.push_back(key);
    }

    std::size_t i = 0;
    while (i < changed.size()) {
      // Extent of this run of consecutive changed addresses.
      std::size_t runEnd = i + 1;
      while (runEnd < changed.size() &&
             changed[runEnd] == changed[runEnd - 1] + 1)
        ++runEnd;

      while (i < runEnd) {
        const std::uint64_t base = changed[i];
        const StoredByte &first = now.at(base);
        const std::uint64_t srcBytes = byteCount(bvWidth(first.source));

        // If this byte starts a value that was written whole, and every one of
        // its remaining bytes also changed and is still intact, report the
        // whole value - that is exactly readBytes' fast path, so the delta
        // carries the original expression rather than a concat of extracts.
        std::uint64_t n = 1;
        if (first.index == 0 && srcBytes > 1 && srcBytes <= kMaxRunBytes &&
            i + srcBytes <= runEnd) {
          bool intact = true;
          for (std::uint64_t k = 1; intact && k < srcBytes; ++k) {
            const auto it = now.find(base + k);
            intact = it != now.end() && it->second.index == k &&
                     it->second.source.id() == first.source.id();
          }
          if (intact)
            n = srcBytes;
        }

        const auto width = static_cast<Width>(n * 8);
        out.push_back(Delta{kind, base, width,
                            readBytes(now, base, width, readKind)});
        i += n;
      }
    }
  };

  scan(regBytes_, before.regBytes_, Delta::Kind::Register, "reg");
  scan(memBytes_, before.memBytes_, Delta::Kind::Memory, "mem");
  return out;
}

// -- merging ----------------------------------------------------------------

z3::expr SymbolicState::joinGuarded(const SymbolicState &incoming,
                                    const z3::expr &condition) {
  if (ctx_ != incoming.ctx_ || !condition.is_bool() ||
      &condition.ctx() != ctx_ || memoryEffects_ || incoming.memoryEffects_ ||
      accessTrace_ || incoming.accessTrace_ ||
      opts_.symbolizeUnmappedReads != incoming.opts_.symbolizeUnmappedReads)
    throw std::invalid_argument(
            "guarded join requires ordinary boundary states in one context");
  if (images_.size() != incoming.images_.size())
    throw std::invalid_argument("guarded join requires shared concrete images");
  for (std::size_t i = 0; i < images_.size(); ++i)
    if (images_[i].base != incoming.images_[i].base ||
        images_[i].bytes != incoming.images_[i].bytes)
      throw std::invalid_argument(
              "guarded join requires shared concrete images");

  z3::expr bad = ctx_->bool_val(false);
  auto join = [&](ByteStore &mine, const ByteStore &theirs,
                  std::string_view kind) {
    std::vector<std::uint64_t> keys;
    auto a = mine.begin();
    auto b = theirs.begin();
    while (a != mine.end() || b != theirs.end()) {
      const auto key =
              b == theirs.end() || (a != mine.end() && a->first <= b->first)
                      ? a->first
                      : b->first;
      const bool same = a != mine.end() && b != theirs.end() &&
                        a->first == key && b->first == key &&
                        a->second.index == b->second.index &&
                        a->second.source.id() == b->second.source.id();
      if (a != mine.end() && a->first == key)
        ++a;
      if (b != theirs.end() && b->first == key)
        ++b;
      if (!same)
        keys.push_back(key);
    }
    for (std::size_t i = 0; i < keys.size();) {
      std::size_t n = 1;
      while (n < 8 && i + n < keys.size() && keys[i + n] == keys[i] + n)
        ++n;
      const auto width = static_cast<Width>(n * 8);
      const auto old = readBytes(mine, keys[i], width, kind);
      const auto other = incoming.readBytes(theirs, keys[i], width, kind);
      if (!z3::eq(old, other)) {
        writeBytes(mine, keys[i], z3::ite(condition, other, old).simplify(),
                   width);
        const auto actual = readBytes(mine, keys[i], width, kind);
        bad = bad || z3::ite(condition, actual != other, actual != old);
      }
      i += n;
    }
  };
  join(regBytes_, incoming.regBytes_, "reg");
  join(memBytes_, incoming.memBytes_, "mem");

  // Assumptions from two mutually exclusive paths must be joined, not unioned.
  std::size_t common = 0;
  while (common < constraints_.size() &&
         common < incoming.constraints_.size() &&
         z3::eq(constraints_[common], incoming.constraints_[common]))
    ++common;
  auto suffix = [&](const std::vector<z3::expr> &items) {
    z3::expr_vector rest(*ctx_);
    for (std::size_t i = common; i < items.size(); ++i)
      rest.push_back(items[i]);
    return z3::mk_and(rest);
  };
  const auto expected = z3::ite(condition, suffix(incoming.constraints_),
                                suffix(constraints_));
  constraints_.erase(constraints_.begin() + common, constraints_.end());
  constraints_.push_back(expected.simplify());
  bad = bad || (constraints_.back() != expected);
  // A later read is entry-dependent if any joined path has not written it.
  for (auto &trace: callTraces_) {
    const auto other =
            std::find_if(incoming.callTraces_.begin(),
                         incoming.callTraces_.end(), [&](const auto &item) {
                           return item.unionTrace == trace.unionTrace;
                         });
    if (other == incoming.callTraces_.end())
      trace.unionTrace->invalidateSummary();
    else
      std::erase_if(trace.written, [&](const auto &byte) {
        return !other->written.contains(byte);
      });
  }
  temps_.clear();
  symbols_.insert(incoming.symbols_.begin(), incoming.symbols_.end());
  regions_.insert(incoming.regions_.begin(), incoming.regions_.end());
  return bad;
}

std::vector<SymbolicState::Delta>
SymbolicState::merge(const SymbolicState &incoming, std::string_view tag) {
  invalidateCallTraces();
  if (memoryEffects_ || incoming.memoryEffects_)
    throw std::invalid_argument("merge requires explicit effect-path joining, "
                                "not register widening");
  std::vector<Delta> out;
  const std::string prefix = "top@" + std::string(tag) + "!";

  // Widest run symbolised as one variable. Kept to 64 bits so every variable
  // a merge makes can be compared against a host integer.
  constexpr std::uint64_t kMaxRunBytes = 8;

  auto join = [&](ByteStore &mine, const ByteStore &theirs, bool images,
                  Delta::Kind kind, char letter) {
    // A byte an earlier merge under this tag already turned into a variable.
    auto isTop = [&](const StoredByte &b) {
      return b.source.is_const() && !b.source.is_numeral() &&
             b.source.decl().name().str().rfind(prefix, 0) == 0;
    };

    auto same = [&](std::uint64_t key) {
      const auto a = mine.find(key);
      const auto b = theirs.find(key);
      // Z3 hash-conses its AST, so equal ids mean the same expression.
      if (a != mine.end() && b != theirs.end() &&
          a->second.index == b->second.index &&
          a->second.source.id() == b->second.source.id())
        return true;
      // Different expressions can still be the same literal - and one side
      // may hold it in the overlay while the other reads it off an image.
      const auto ca = concreteByte(mine, key, images);
      const auto cb = incoming.concreteByte(theirs, key, images);
      return ca && cb && *ca == *cb;
    };

    // Walk the union of both key sets, in address order.
    std::vector<std::uint64_t> differing;
    auto a = mine.begin();
    auto b = theirs.begin();
    while (a != mine.end() || b != theirs.end()) {
      std::uint64_t key;
      if (b == theirs.end() || (a != mine.end() && a->first <= b->first))
        key = a->first;
      else
        key = b->first;
      const bool top = a != mine.end() && a->first == key && isTop(a->second);
      if (a != mine.end() && a->first == key)
        ++a;
      if (b != theirs.end() && b->first == key)
        ++b;
      if (!top && !same(key))
        differing.push_back(key);
    }

    // The whole written value a byte belongs to, as [start, start + n): the
    // unit to symbolise. One differing byte of a 64-bit counter means the
    // counter varies, not that its low byte does - symbolising byte by byte
    // would leave the rest a literal and take one more merge per byte to
    // find out otherwise.
    auto extentOf = [](const ByteStore &store, std::uint64_t key)
            -> std::pair<std::uint64_t, std::uint64_t> {
      const auto it = store.find(key);
      if (it == store.end())
        return {key, 1};
      const std::uint64_t n = byteCount(bvWidth(it->second.source));
      const std::uint64_t start = key - it->second.index;
      if (n <= 1 || n > kMaxRunBytes)
        return {key, 1};
      for (std::uint64_t k = 0; k < n; ++k) {
        const auto b = store.find(start + k);
        if (b == store.end() || b->second.index != k ||
            b->second.source.id() != it->second.source.id())
          return {key, 1};
      }
      return {start, n};
    };

    // Prefer the shape of the incoming value, then of the one it replaces.
    // Extents are taken in address order and one that starts inside an
    // earlier one is dropped, so no byte is symbolised twice.
    std::uint64_t coveredUntil = 0;
    bool any = false;
    for (const std::uint64_t key : differing) {
      if (any && key < coveredUntil)
        continue;
      auto [start, n] = extentOf(theirs, key);
      if (n == 1)
        std::tie(start, n) = extentOf(mine, key);
      if (any && start < coveredUntil) {
        start = key;
        n = 1;
      }

      const auto width = static_cast<Width>(n * 8);
      const z3::expr top =
              symbol(prefix + letter + hex(start) + ":" + std::to_string(width),
                     width);
      writeBytes(mine, start, top, width);
      out.push_back(Delta{kind, start, width, top});
      coveredUntil = start + n;
      any = true;
    }
  };

  join(regBytes_, incoming.regBytes_, /*images=*/false, Delta::Kind::Register,
       'r');
  join(memBytes_, incoming.memBytes_, /*images=*/true, Delta::Kind::Memory,
       'm');

  // Variables the incoming path made are still mentioned by the bytes both
  // sides agree on, so a model has to be able to report them.
  for (const auto &[name, sym] : incoming.symbols_)
    symbols_.emplace(name, sym);
  for (const auto &[name, size] : incoming.regions_)
    regions_.emplace(name, size);

  return out;
}

// -- registers --------------------------------------------------------------

void SymbolicState::writeRegister(const Reg &r, const z3::expr &value) {
  observeCallAccess(false, r.offset,
      opts_.zeroExtendOn32BitWrite && r.width == 32 ? 8 : byteCount(r.width), true);
  if (accessTrace_) accessTrace_->observe(false, r.offset,
      opts_.zeroExtendOn32BitWrite && r.width == 32 ? 8 : byteCount(r.width), true);
  writeBytes(regBytes_, r.offset, zeroCoerce(value, r.width), r.width);

  // x86-64 / AArch64: a 32-bit write clears the upper half of the 64-bit
  // parent. 8- and 16-bit writes merge into the parent on both, which the
  // byte-granular store already gets right for free.
  if (opts_.zeroExtendOn32BitWrite && r.width == 32) {
    for (std::uint64_t i = 4; i < 8; ++i)
      regBytes_.insert_or_assign(r.offset + i,
                                 StoredByte{bvVal(*ctx_, 0, 8), 0});
  }
}

void SymbolicState::writeRegister(const Reg &r, std::uint64_t value) {
  writeRegister(r, bvVal(*ctx_, maskTo(value, r.width), r.width));
}

z3::expr SymbolicState::readRegister(const Reg &r) const {
  observeCallAccess(false, r.offset, byteCount(r.width), false);
  if (accessTrace_)
    accessTrace_->observe(false, r.offset, byteCount(r.width), false);
  return readBytes(regBytes_, r.offset, r.width, "reg");
}

bool SymbolicState::isRegisterDefined(const Reg &r) const {
  const std::uint64_t n = byteCount(r.width);
  for (std::uint64_t i = 0; i < n; ++i)
    if (regBytes_.find(r.offset + i) == regBytes_.end())
      return false;
  return true;
}

z3::expr SymbolicState::symbolizeRegister(const Reg &r, std::string_view name) {
  const std::string chosen =
          name.empty() ? (r.name.empty() ? "reg_" + std::to_string(r.offset)
                                         : r.name)
                       : std::string(name);
  z3::expr s = symbol(chosen, r.width);
  writeRegister(r, s);
  return s;
}

// -- temporaries ------------------------------------------------------------

void SymbolicState::writeTemp(const Temp &t, const z3::expr &value) {
  temps_.insert_or_assign(t.id, zeroCoerce(value, t.width));
}

std::optional<z3::expr> SymbolicState::readTemp(const Temp &t) const {
  auto it = temps_.find(t.id);
  if (it == temps_.end())
    return std::nullopt;
  return it->second;
}

// -- memory -----------------------------------------------------------------

void SymbolicState::writeMemory(std::uint64_t addr, const z3::expr &value) {
  observeCallAccess(true, addr, byteCount(bvWidth(value)), true);
  if (accessTrace_) accessTrace_->observe(true, addr, byteCount(bvWidth(value)), true);
  writeBytes(memBytes_, addr, value, bvWidth(value));
}

void SymbolicState::writeMemory(std::uint64_t addr,
                                const std::vector<std::uint8_t> &bytes) {
  observeCallAccess(true, addr, bytes.size(), true);
  if (accessTrace_) accessTrace_->observe(true, addr, bytes.size(), true);
  if (bytes.size() >= kImageThreshold) {
    // The image replaces whatever was there, overlay included.
    memBytes_.erase(memBytes_.lower_bound(addr),
                    memBytes_.lower_bound(addr + bytes.size()));
    images_.push_back(
            {addr, std::make_shared<const std::vector<std::uint8_t>>(bytes)});
    return;
  }
  for (std::size_t i = 0; i < bytes.size(); ++i)
    memBytes_.insert_or_assign(addr + i,
                               StoredByte{bvVal(*ctx_, bytes[i], 8), 0});
}

z3::expr SymbolicState::readMemory(std::uint64_t addr, Width width) const {
  observeCallAccess(true, addr, byteCount(width), false);
  if (accessTrace_) accessTrace_->observe(true, addr, byteCount(width), false);
  return readBytes(memBytes_, addr, width, "mem");
}

bool SymbolicState::isMemoryDefined(std::uint64_t addr, Width width) const {
  const std::uint64_t n = byteCount(width);
  for (std::uint64_t i = 0; i < n; ++i)
    if (memBytes_.find(addr + i) == memBytes_.end() && !imageByte(addr + i))
      return false;
  return true;
}

z3::expr SymbolicState::symbolizeMemory(std::uint64_t addr, std::uint64_t size,
                                        std::string_view name) {
  const std::string region(name);
  regions_.insert_or_assign(region, size);

  for (std::uint64_t i = 0; i < size; ++i)
    memBytes_.insert_or_assign(
            addr + i,
            StoredByte{symbol(region + "[" + std::to_string(i) + "]", 8), 0});

  // Handing back the whole region as one value is only meaningful while it
  // fits a bitvector we can compare against a 64-bit constant.
  const Width width =
          static_cast<Width>(std::clamp<std::uint64_t>(size, 1, 8) * 8);
  return readMemory(addr, width);
}

// -- constraints ------------------------------------------------------------

void SymbolicState::addConstraint(const z3::expr &c) {
  constraints_.push_back(c);
}

bool SymbolicState::hasMemoryPrefix(std::uint32_t upper) const {
  const auto low = static_cast<std::uint64_t>(upper) << 32;
  auto it = memBytes_.lower_bound(low);
  if (it != memBytes_.end() && (it->first >> 32) == upper) return true;
  for (const auto &image : images_)
    if ((image.base >> 32) <= upper &&
        ((image.base + image.bytes->size() - 1) >> 32) >= upper) return true;
  return false;
}

void SymbolicState::specialize(const z3::expr &expression,
                               const z3::expr &value) {
  // Only substitute an equality justified by the retained path guard. Memoize
  // common sources: a qword is represented by eight references to one term.
  z3::expr_vector from(*ctx_), to(*ctx_);
  from.push_back(expression);
  to.push_back(value);
  specialize(from, to);
}

void SymbolicState::specialize(const z3::expr_vector &from,
                               const z3::expr_vector &to) {
  // Keep original ASTs alive too: replacing the last stored reference can
  // release an AST id, which Z3 may reuse during a later rewrite in this pass.
  std::map<unsigned, std::pair<z3::expr, z3::expr>> memo;
  auto rewrite = [&](z3::expr &source) {
    if (source.is_numeral())
      return;
    const auto id = source.id();
    if (auto it = memo.find(id); it != memo.end()) {
      source = it->second.second;
      return;
    }
    z3::expr result = source.substitute(from, to);
    if (!z3::eq(result, source)) {
      result = result.simplify();
    } else {
      // A guard/address probe can use a normalized spelling. Only keep that
      // spelling when the substitution actually affects this source. In
      // particular, forking a pointer must not bit-split unrelated user data.
      auto normalized = source.simplify();
      auto replaced = normalized.substitute(from, to);
      if (!z3::eq(normalized, replaced))
        result = replaced.simplify();
    }
    memo.emplace(id, std::make_pair(source, result));
    source = result;
  };
  for (auto &[_, byte]: regBytes_)
    rewrite(byte.source);
  for (auto &[_, byte]: memBytes_)
    rewrite(byte.source);
  for (auto &[_, temp]: temps_)
    rewrite(temp);
}

// ---------------------------------------------------------------------------
// SymbolicExecutor - construction
// ---------------------------------------------------------------------------

SymbolicExecutor::SymbolicExecutor(SymbolicOptions opts) :
  ownedCtx_(std::make_shared<z3::context>()), ctx_(ownedCtx_.get()),
    opts_(std::move(opts)), state_(*ctx_, opts_), solver_(*ctx_) {
  z3::params p(*ctx_);
  p.set("timeout", opts_.solverTimeoutMs);
  solver_.set(p);
}

SymbolicExecutor::SymbolicExecutor(z3::context &ctx, SymbolicOptions opts) :
    ctx_(&ctx), opts_(std::move(opts)), state_(*ctx_, opts_), solver_(*ctx_) {
  z3::params p(*ctx_);
  p.set("timeout", opts_.solverTimeoutMs);
  solver_.set(p);
}

void SymbolicExecutor::reset() {
  state_ = SymbolicState(*ctx_, opts_);
  solver_.reset();
  assertedConstraints_ = 0;
  satisfiableConstraints_.reset();
}

void SymbolicExecutor::setState(SymbolicState state) {
  state_ = std::move(state);
  solver_.reset();
  assertedConstraints_ = 0;
  satisfiableConstraints_.reset();
}

z3::expr SymbolicExecutor::bv(std::uint64_t value, Width width) const {
  return bvVal(*ctx_, maskTo(value, width), width);
}

// -- machine setup ----------------------------------------------------------

void SymbolicExecutor::setRegister(const Reg &r, std::uint64_t value) {
  state_.writeRegister(r, value);
}

void SymbolicExecutor::setRegister(const Reg &r, const z3::expr &value) {
  state_.writeRegister(r, value);
}

z3::expr SymbolicExecutor::symbolizeRegister(const Reg &r,
                                             std::string_view name) {
  return state_.symbolizeRegister(r, name);
}

void SymbolicExecutor::mapMemory(std::uint64_t addr,
                                 const std::vector<std::uint8_t> &bytes) {
  state_.writeMemory(addr, bytes);
}

void SymbolicExecutor::setMemory(std::uint64_t addr, const z3::expr &value) {
  state_.writeMemory(addr, value);
}

z3::expr SymbolicExecutor::symbolizeMemory(std::uint64_t addr,
                                           std::uint64_t size,
                                           std::string_view name) {
  return state_.symbolizeMemory(addr, size, name);
}

z3::expr SymbolicExecutor::bindRegisterValue(const Reg &r,
                                             std::string_view name) {
  if (name.empty() || state_.symbols().contains(std::string(name)) ||
      state_.memoryEffects())
    throw std::invalid_argument(
            "register value binding requires a fresh name and ordinary memory");
  const auto original = readRegister(r);
  const auto result = state_.symbol(name, bvWidth(original));
  z3::expr_vector from(*ctx_), to(*ctx_);
  std::set<unsigned> seen;
  auto add = [&](const z3::expr &old, const z3::expr &replacement) {
    if (!old.is_numeral() && seen.insert(old.id()).second) {
      from.push_back(old);
      to.push_back(replacement);
    }
  };
  add(original, result);
  add(original.simplify(), result);
  for (unsigned width: {32u, 16u, 8u}) {
    if (width >= bvWidth(original))
      continue;
    for (unsigned low = 0; low + width <= bvWidth(original); low += width) {
      const auto old = original.extract(low + width - 1, low);
      const auto replacement = result.extract(low + width - 1, low);
      add(old, replacement);
      add(old.simplify(), replacement);
    }
  }
  // Every simultaneous replacement follows from this definitional extension.
  // Original constraints and image bytes are retained; no solver assumption
  // about the original inputs is introduced or removed.
  assume(result == original);
  state_.specialize(from, to);
  state_.writeRegister(r, result);
  return result;
}

void SymbolicExecutor::assume(const z3::expr &c) { state_.addConstraint(c); }

std::optional<bool>
SymbolicExecutor::specializeEquality(const z3::expr &equality) {
  if (&equality.ctx() != ctx_ || !equality.is_bool() || state_.memoryEffects())
    return std::nullopt;
  auto equation = equality;
  // parse_condition represents its assertions as a conjunction. Keep the
  // equality's original operands: simplifying `predicate == true` first would
  // erase the very substitution that the caller asked us to justify.
  while (equation.is_and() && equation.num_args() == 1)
    equation = equation.arg(0);
  if (!equation.is_eq())
    return std::nullopt;
  const auto justified = proves(equation);
  if (justified && *justified)
    state_.specialize(equation.arg(0), equation.arg(1));
  return justified;
}

void SymbolicExecutor::setConcreteOpaque(OpaqueKind kind, std::uint64_t selector,
                                         std::vector<std::uint64_t> results) {
  if (results.empty()) concreteOpaque_.erase({kind, selector});
  else concreteOpaque_[{kind, selector}] = std::move(results);
}

// -- reading ----------------------------------------------------------------

z3::expr SymbolicExecutor::readRegister(const Reg &r) const {
  return state_.readRegister(r);
}

z3::expr SymbolicExecutor::readMemory(std::uint64_t addr, Width width) const {
  return state_.readMemory(addr, width);
}

std::optional<z3::expr> SymbolicExecutor::readTemp(const Temp &t) const {
  return state_.readTemp(t);
}

// ---------------------------------------------------------------------------
// SymbolicExecutor - expression construction
// ---------------------------------------------------------------------------

z3::expr SymbolicExecutor::eval(const Value &v) const {
  if (const auto *c = std::get_if<Const>(&v))
    return bvVal(*ctx_, maskTo(c->value, c->width), c->width);
  if (const auto *r = std::get_if<Reg>(&v))
    return state_.readRegister(*r);

  const auto &t = std::get<Temp>(v);
  if (auto e = state_.readTemp(t))
    return *e;
  // Reading a Temp that was never defined means the block is not in SSA form
  // (a lifter bug, or a block starting mid-sequence). Treat it the same way
  // as an unwritten register: a fresh free variable, so execution continues
  // and the solver can still say something useful about the rest.
  return state_.symbol("t" + std::to_string(t.id), t.width);
}

z3::expr SymbolicExecutor::coerce(const z3::expr &e, Width width) const {
  return zeroCoerce(e, width);
}

void SymbolicExecutor::writeDst(const Value &dst, const z3::expr &value) {
  if (const auto *t = std::get_if<Temp>(&dst)) {
    state_.writeTemp(*t, value);
    return;
  }
  if (const auto *r = std::get_if<Reg>(&dst)) {
    state_.writeRegister(*r, value);
    return;
  }
  // A Const destination is malformed IGNIL; step() rejects it before we get
  // here, so there is nothing to do.
}

z3::expr SymbolicExecutor::shift(Opcode op, const z3::expr &lhs,
                                 const z3::expr &rhs) const {
  // Do the shift in a width wide enough to hold both operands, so an amount
  // that overshoots the value's width still produces the all-zero (SHL/SHR)
  // or all-sign (SAR) result rather than wrapping. This is exactly the
  // behaviour IGNILSimplify folds constant shifts to.
  const Width w = std::max(bvWidth(lhs), bvWidth(rhs));
  const z3::expr amount = zeroCoerce(rhs, w);

  switch (op) {
    case Opcode::SHL:
      return z3::shl(zeroCoerce(lhs, w), amount);
    case Opcode::SHR:
      return z3::lshr(zeroCoerce(lhs, w), amount);
    default: // SAR
      return z3::ashr(signCoerce(lhs, w), amount);
  }
}

z3::expr SymbolicExecutor::binary(Opcode op, const z3::expr &lhs,
                                  const z3::expr &rhs, Width dstWidth) const {
  if (op == Opcode::SHL || op == Opcode::SHR || op == Opcode::SAR)
    return zeroCoerce(fold::local(shift(op, lhs, rhs)), dstWidth);

  if (op == Opcode::FADD || op == Opcode::FSUB || op == Opcode::FMUL ||
      op == Opcode::FDIV)
    return zeroCoerce(floatBinary(op, lhs, rhs), dstWidth);

  // Widen both operands to a common width before computing, matching how
  // IGNILSimplify folds the same op on constants. For well-formed IGNIL every
  // width here is already equal and this is a no-op.
  const Width w = isComparison(op)
                          ? std::max(bvWidth(lhs), bvWidth(rhs))
                          : std::max({dstWidth, bvWidth(lhs), bvWidth(rhs)});
  const bool sign = isSignedOp(op);
  const z3::expr a = sign ? signCoerce(lhs, w) : zeroCoerce(lhs, w);
  const z3::expr b = sign ? signCoerce(rhs, w) : zeroCoerce(rhs, w);

  const auto boolTo1 = [&](const z3::expr &pred) {
    return fold::local(z3::ite(fold::local(pred), bvVal(*ctx_, 1, 1), bvVal(*ctx_, 0, 1)));
  };

  z3::expr result = [&]() -> z3::expr {
    switch (op) {
      case Opcode::ADD: return a + b;
      case Opcode::SUB: return a - b;
      case Opcode::MUL: return a * b;
      case Opcode::AND: return a & b;
      case Opcode::OR: return a | b;
      case Opcode::XOR: return a ^ b;
      // Z3's division and remainder are total: x/0 is all-ones for unsigned
      // and -1/1 for signed, x%0 is x. IGNIL leaves division by zero
      // unspecified (IGNILSimplify refuses to fold it), so a block that can
      // divide by zero gets Z3's answer rather than a trap - constrain the
      // divisor if that matters.
      case Opcode::UDIV: return z3::udiv(a, b);
      case Opcode::SDIV: return a / b;
      case Opcode::UMOD: return z3::urem(a, b);
      // srem, not smod: IGNILSimplify folds SMOD with C's %, which truncates
      // toward zero and takes the sign of the dividend.
      case Opcode::SMOD: return z3::srem(a, b);
      case Opcode::EQ: return boolTo1(a == b);
      case Opcode::NEQ: return boolTo1(a != b);
      case Opcode::ULT: return boolTo1(z3::ult(a, b));
      case Opcode::ULE: return boolTo1(z3::ule(a, b));
      case Opcode::UGT: return boolTo1(z3::ugt(a, b));
      case Opcode::UGE: return boolTo1(z3::uge(a, b));
      case Opcode::SLT: return boolTo1(a < b);
      case Opcode::SLE: return boolTo1(a <= b);
      case Opcode::SGT: return boolTo1(a > b);
      default: return boolTo1(a >= b); // SGE
    }
  }();

  return zeroCoerce(fold::local(result), dstWidth);
}

z3::expr SymbolicExecutor::unary(Opcode op, const z3::expr &src,
                                 Width dstWidth) const {
  switch (op) {
    case Opcode::NEG: {
      const Width w = std::max(dstWidth, bvWidth(src));
      return zeroCoerce(-zeroCoerce(src, w), dstWidth);
    }
    case Opcode::NOT: {
      const Width w = std::max(dstWidth, bvWidth(src));
      return zeroCoerce(~zeroCoerce(src, w), dstWidth);
    }
    case Opcode::SEXT:
      return signCoerce(src, dstWidth);
    case Opcode::SITOFP:
      return z3::sbv_to_fpa(src, float64Sort(*ctx_)).mk_to_ieee_bv();
    case Opcode::FPTOSI: {
      // Truncate toward zero, which is what CVTTSD2SI and every C cast do -
      // not the context's default round-to-nearest.
      const z3::expr f = src.mk_from_ieee_bv(float64Sort(*ctx_));
      const z3::expr rtz =
              z3::to_expr(*ctx_, Z3_mk_fpa_round_toward_zero(*ctx_));
      return z3::to_expr(*ctx_,
                         Z3_mk_fpa_to_sbv(*ctx_, rtz, f, dstWidth));
    }
    default: // COPY, ZEXT, TRUNC
      return zeroCoerce(src, dstWidth);
  }
}

z3::expr SymbolicExecutor::floatBinary(Opcode op, const z3::expr &lhs,
                                       const z3::expr &rhs) const {
  const z3::sort f64 = float64Sort(*ctx_);
  const z3::expr a = zeroCoerce(lhs, 64).mk_from_ieee_bv(f64);
  const z3::expr b = zeroCoerce(rhs, 64).mk_from_ieee_bv(f64);

  z3::expr r = [&]() -> z3::expr {
    switch (op) {
      case Opcode::FADD: return a + b;
      case Opcode::FSUB: return a - b;
      case Opcode::FMUL: return a * b;
      default: return a / b; // FDIV
    }
  }();
  return r.mk_to_ieee_bv();
}

// ---------------------------------------------------------------------------
// SymbolicExecutor - solver
// ---------------------------------------------------------------------------

z3::solver &SymbolicExecutor::solver() {
  const auto &cs = state_.constraints();
  if (cs.size() < assertedConstraints_) {
    solver_.reset();
    assertedConstraints_ = 0;
  }
  for (std::size_t i = assertedConstraints_; i < cs.size(); ++i)
    solver_.add(cs[i]);
  assertedConstraints_ = cs.size();
  return solver_;
}

std::optional<bool> SymbolicExecutor::isSatisfiable(const z3::expr &condition) {
  // A condition that folds to a literal needs no solver: false is false under
  // any constraints, and true is satisfiable whenever there are none to
  // contradict it.
  const z3::expr folded = condition.simplify();
  if (folded.is_false())
    return false;
  if (folded.is_true() && (state_.constraints().empty() ||
                           satisfiableConstraints_ == state_.constraints().size()))
    return true;

  z3::solver &s = solver();
  s.push();
  s.add(condition);
  const z3::check_result r = s.check();
  if (r == z3::sat)
    satisfiableConstraints_ = state_.constraints().size();
  s.pop();

  if (r == z3::unknown)
    return std::nullopt;
  return r == z3::sat;
}

std::optional<bool> SymbolicExecutor::proves(const z3::expr &condition) {
  auto counterexample = isSatisfiable(!condition);
  if (!counterexample)
    return std::nullopt;
  return !*counterexample;
}

std::optional<std::uint64_t> SymbolicExecutor::evaluate(const z3::expr &e) {
  // A literal is its own unique value, whatever the constraints say - unless
  // they are unsatisfiable, and that is rare enough not to pay two solver
  // calls on every concrete register read to find out.
  if (const z3::expr folded = e.simplify();
      folded.is_numeral() && bvWidth(folded) <= 64)
    return folded.get_numeral_uint64();

  z3::solver &s = solver();

  s.push();
  const z3::check_result r = s.check();
  if (r != z3::sat) {
    s.pop();
    return std::nullopt;
  }
  satisfiableConstraints_ = state_.constraints().size();
  const z3::expr candidate = s.get_model().eval(e, /*model_completion=*/true);
  s.pop();

  if (!candidate.is_numeral())
    return std::nullopt;

  // Unique only if no model disagrees - the same test ValueEnumerator uses to
  // decide an "obfuscated" value is really a constant.
  s.push();
  s.add(e != candidate);
  const z3::check_result other = s.check();
  s.pop();

  if (other != z3::unsat)
    return std::nullopt;
  return candidate.get_numeral_uint64();
}

std::vector<std::uint64_t> SymbolicExecutor::enumerate(const z3::expr &e,
                                                       std::size_t max,
                                                       bool *exhaustive) {
  std::vector<std::uint64_t> out;
  if (exhaustive)
    *exhaustive = false;
  if (max == 0)
    return out;

  z3::solver &s = solver();
  s.push();

  bool ranOut = false;
  while (out.size() < max) {
    const z3::check_result r = s.check();
    if (r == z3::unsat) {
      ranOut = true;
      break;
    }
    if (r == z3::unknown)
      break;

    satisfiableConstraints_ = state_.constraints().size();
    const z3::expr v = s.get_model().eval(e, /*model_completion=*/true);
    if (!v.is_numeral())
      break;
    out.push_back(v.get_numeral_uint64());
    s.add(e != v);
  }

  // Filling the budget is not proof there is nothing else; one more query
  // settles it, so a set of exactly `max` values is still reported complete.
  if (!ranOut && out.size() == max && s.check() == z3::unsat)
    ranOut = true;

  s.pop();
  if (exhaustive)
    *exhaustive = ranOut;
  return out;
}

std::optional<Solution> SymbolicExecutor::solve() {
  return solve(std::vector<z3::expr>{});
}

std::optional<Solution> SymbolicExecutor::solve(const z3::expr &goal) {
  return solve(std::vector<z3::expr>{goal});
}

std::optional<Solution>
SymbolicExecutor::solve(const std::vector<z3::expr> &goals) {
  z3::solver &s = solver();
  s.push();
  for (const auto &g : goals)
    s.add(g);

  const z3::check_result r = s.check();
  if (r != z3::sat) {
    s.pop();
    return std::nullopt;
  }

  satisfiableConstraints_ = state_.constraints().size();
  const z3::model m = s.get_model();
  Solution sol;
  for (const auto &[name, sym] : state_.symbols()) {
    const z3::expr v = m.eval(sym, /*model_completion=*/true);
    if (v.is_numeral())
      sol.values_.emplace(name, v.get_numeral_uint64());
  }
  sol.regionSizes_ = state_.regions();

  s.pop();
  return sol;
}

// ---------------------------------------------------------------------------
// SymbolicExecutor - execution
// ---------------------------------------------------------------------------

void SymbolicExecutor::warn(RunResult &result, const Op &op,
                            std::string message) {
  result.warnings.push_back({op.address, std::move(message)});
}

namespace {
void impliedReadSelectors(const z3::expr &expression, z3::solver &probe,
                          unsigned solverTimeoutMs, z3::expr_vector &from,
                          z3::expr_vector &to);
} // namespace

std::optional<std::vector<std::uint64_t>>
SymbolicExecutor::concretize(const z3::expr &addr, std::size_t max,
                             const Op &op, std::string_view what,
                             RunResult &result) {
  if (addr.is_numeral())
    return std::vector<std::uint64_t>{addr.get_numeral_uint64()};

  bool exhaustive = false;
  ++result.stats.solverQueries;
  std::vector<std::uint64_t> values = enumerate(addr, max, &exhaustive);

  if (!exhaustive) {
    warn(result, op,
         std::string(what) + " has more than " + std::to_string(max) +
                 " possible values (or the solver timed out); left unresolved");
    return std::nullopt;
  }

  result.stats.addressesConcretized += values.size();
  if (values.size() == 1 && !state_.memoryEffects()) {
    // An exhaustive singleton is a proof under the retained path constraints,
    // not just a model value. Feed it back when the value is first derived,
    // not only at the earlier fork where this expression may not yet exist.
    z3::expr_vector from(*ctx_), to(*ctx_);
    from.push_back(addr);
    to.push_back(bvVal(*ctx_, values.front(), bvWidth(addr)));
    impliedReadSelectors(addr, solver(), opts_.solverTimeoutMs,
                         from, to);
    state_.specialize(from, to);
  }
  return values;
}

namespace {
struct LiteralArm { z3::expr guard; z3::expr value; };
// At most two arms and a tiny wrapper cone. Conditions are never traversed:
// their full symbolic meaning is retained as the guards. Ordinary symbolic
// data is rejected, not enumerated or concretized from a model.
bool literalReadArms(const z3::expr &e, std::vector<LiteralArm> &arms,
                     unsigned &budget) {
  // IGNIL's branchless select becomes arithmetic on an ite(cond, 0, 1).
  // Treat its condition as an opaque boundary, never expand the source-input
  // cone. Correlated occurrences are replaced together, avoiding a Cartesian
  // explosion of the same selector repeated in multiple bit slices.
  std::vector<z3::expr> pending{e}, selectors;
  std::map<unsigned, bool> seen;
  std::optional<z3::expr> condition;
  while (!pending.empty()) {
    if (budget == 0) return false;
    --budget;
    auto node = pending.back(); pending.pop_back();
    if (!seen.emplace(node.id(), true).second) continue;
    if (node.is_numeral()) continue;
    if (!node.is_app()) return false;
    if (node.decl().decl_kind() == Z3_OP_ITE && node.is_bv() &&
        node.arg(1).is_numeral() && node.arg(2).is_numeral()) {
      if (!condition) condition = node.arg(0);
      if (!z3::eq(*condition, node.arg(0)) &&
          !z3::eq((!*condition).simplify(), node.arg(0))) return false;
      selectors.push_back(node);
      continue;
    }
    if (node.num_args() == 0 || !node.is_bv()) return false;
    for (unsigned i = 0; i < node.num_args(); ++i) pending.push_back(node.arg(i));
  }
  if (!condition) return false;
  for (bool truth : {true, false}) {
    z3::expr_vector from(e.ctx()), to(e.ctx());
    for (const auto &selector : selectors) {
      bool same = z3::eq(*condition, selector.arg(0));
      from.push_back(selector);
      to.push_back(selector.arg(truth == same ? 1 : 2));
    }
    auto selected = e;
    selected = selected.substitute(from, to).simplify();
    if (!selected.is_numeral() || selected.get_sort().bv_size() > 64) return false;
    arms.push_back({truth ? *condition : !*condition, selected});
  }
  return true;
}
// A pointer equality need not syntactically expose its selector: x86 flag
// lowering can encode it as XORs of correlated predicates and bit masks. Prove
// fixed Boolean / one-bit subterms under the *full* selected path, rather than
// carrying this decoder dependency through every subsequent memory address.
// Model values are only candidates; only UNSAT disequalities justify rewrites.
void impliedReadSelectors(const z3::expr &expression, z3::solver &probe,
                          unsigned solverTimeoutMs, z3::expr_vector &from,
                          z3::expr_vector &to) {
  auto &ctx = expression.ctx();
  std::vector<z3::expr> pending{expression}, candidates;
  std::map<unsigned, bool> seen;
  unsigned budget = 512;
  while (!pending.empty() && budget--) {
    auto node = pending.back();
    pending.pop_back();
    if (!seen.emplace(node.id(), true).second || !node.is_app())
      continue;
    if (node.num_args() &&
        (node.is_bool() || (node.is_bv() && bvWidth(node) == 1)))
      candidates.push_back(node);
    for (unsigned i = 0; i < node.num_args(); ++i)
      pending.push_back(node.arg(i));
  }
  if (candidates.empty())
    return;

  const auto deadline =
          std::chrono::steady_clock::now() + std::chrono::milliseconds(100);
  // Reuse the path solver's learned clauses. Rebuilding a solver for the
  // same retained path can exhaust the short probe timeout before even
  // obtaining a model, leaving a selected decoder bit symbolic indefinitely.
  struct RestoreTimeout {
    z3::solver &solver;
    unsigned timeout;
    ~RestoreTimeout() {
      z3::params params(solver.ctx());
      params.set("timeout", timeout);
      solver.set(params);
    }
  } restore{probe, solverTimeoutMs};
  z3::params params(ctx);
  params.set("timeout", solverTimeoutMs ? std::min(solverTimeoutMs, 20u) : 20u);
  probe.set(params);
  if (probe.check() != z3::sat)
    return;
  const auto model = probe.get_model();
  unsigned queries = 0;
  for (auto candidate: candidates) {
    if (std::chrono::steady_clock::now() >= deadline || queries >= 32)
      break;
    auto reduced = candidate.substitute(from, to).simplify();
    auto value = model.eval(candidate, true).simplify();
    if (!(value.is_numeral() || value.is_true() || value.is_false()))
      continue;
    if (!z3::eq(reduced, value)) {
      probe.push();
      probe.add(candidate != value);
      ++queries;
      const auto result = probe.check();
      probe.pop();
      if (result != z3::unsat)
        continue;
    }
    from.push_back(candidate);
    to.push_back(value);
  }
}
} // namespace

bool SymbolicExecutor::chooseMemoryRead(const MemoryReadChoice &choice,
                                        std::size_t index) {
  if (index >= choice.values.size() || &choice.expression.ctx() != ctx_ ||
      state_.memoryEffects())
    return false;
  const auto selected =
          bvVal(*ctx_, choice.values[index], bvWidth(choice.expression));
  assume(choice.guards[index]);
  // Keep the original condition as the path guard, but eliminate its mux
  // from the execution state. This is what makes subsequent decoding concrete.
  const auto guard = choice.guards[index].simplify();
  z3::expr_vector from(*ctx_), to(*ctx_);
  if (guard.is_app() && guard.decl().decl_kind() == Z3_OP_NOT) {
    from.push_back(guard.arg(0));
    to.push_back(ctx_->bool_val(false));
  } else {
    from.push_back(guard);
    to.push_back(ctx_->bool_val(true));
  }
  from.push_back(choice.expression);
  to.push_back(selected);
  impliedReadSelectors(choice.expression, solver(), opts_.solverTimeoutMs, from,
                       to);
  state_.specialize(from, to);
  if (choice.valueChoice) {
    // Same invariant as Mergen's buffer rewrite: the slot is equal to this
    // literal under the original selector guard, including overlapping reads.
    state_.writeMemory(choice.slot, selected);
    writeDst(choice.destination, selected);
  } else {
    writeDst(choice.destination,
             state_.readMemory(choice.values[index],
                               widthOf(choice.destination)));
  }
  return true;
}

ExecStatus SymbolicExecutor::stepMemory(const Op &op, RunResult &result) {
  if (auto *effects = state_.memoryEffects()) {
    const bool load = op.opcode == Opcode::LOAD;
    if ((load && (!op.dst || op.srcs.size() != 1)) ||
        (!load && (op.dst || op.srcs.size() != 2)))
      return ExecStatus::MalformedOp;
    const auto address = eval(op.srcs[0]).simplify();
    const auto width = load ? widthOf(*op.dst) : widthOf(op.srcs[1]);
    if (!address.is_bv() || bvWidth(address) != 64 || !width || width % 8)
      return ExecStatus::UnsupportedOp;
    if (load) {
      writeDst(*op.dst, effects->load(address, width, op.address));
      state_.addConstraint(effects->constraints().back());
    } else {
      effects->store(address, zeroCoerce(eval(op.srcs[1]), width), op.address);
    }
    return ExecStatus::Ok;
  }
  if (op.opcode == Opcode::LOAD) {
    if (!op.dst || op.srcs.size() != 1)
      return ExecStatus::MalformedOp;

    const Width width = widthOf(*op.dst);
    const z3::expr addr = eval(op.srcs[0]).simplify();

    auto candidates =
            concretize(addr, opts_.maxAddressSolutions, op, "load address",
                       result);
    if (!candidates || candidates->empty()) {
      // Either too symbolic to resolve, or the path is infeasible. Either way
      // the loaded value is unknown; a fresh symbol keeps the run going
      // without inventing a wrong answer.
      const z3::expr fresh = state_.symbol(
              "load@" + hex(op.address) + "_" +
                      std::to_string(result.stats.opsExecuted) +
                      (freshTag_.empty() ? "" : "#" + freshTag_),
              width);
      writeDst(*op.dst, fresh);
      if (!candidates)
        result.unresolved.push_back(
                {/*isStore=*/false, op.address, width, addr, fresh});
      return ExecStatus::Ok;
    }

    if (opts_.forkMemoryReads && candidates->size() > 1) {
      MemoryReadChoice choice{false, op.address, 0, 0, *op.dst, addr, *candidates, {}};
      std::vector<LiteralArm> structural;
      unsigned budget = 256;
      const bool recognized = literalReadArms(addr, structural, budget) && structural.size() == 2;
      for (auto value : *candidates) {
        z3::expr guard = addr == bvVal(*ctx_, value, bvWidth(addr));
        if (recognized) for (const auto &arm : structural)
          if (arm.value.get_numeral_uint64() == value) guard = arm.guard;
        choice.guards.push_back(guard);
      }
      result.memoryChoice = std::move(choice);
      return ExecStatus::Ok;
    }

    // Fold the candidates into a select chain. A single candidate - the
    // common case, and every concrete address - collapses to a plain read.
    z3::expr value = state_.readMemory(candidates->back(), width);
    for (auto it = candidates->rbegin() + 1; it != candidates->rend(); ++it)
      value = z3::ite(addr == bvVal(*ctx_, *it, bvWidth(addr)),
                      state_.readMemory(*it, width), value);

    // Keep concrete decoder state concrete, but do not write Z3's global
    // bit-splitting normal form back over an intact symbolic word. Address
    // queries still normalize independently; no model value is selected.
    value = fold::local(value);
    const auto normalized = value.simplify();
    if (normalized.is_numeral()) value = normalized;
    if (opts_.forkMemoryReads && width == 64 && !value.is_numeral() && candidates->size() == 1) {
      std::vector<LiteralArm> arms;
      unsigned budget = 256;
      bool recognized = literalReadArms(normalized, arms, budget) && arms.size() == 2;
      // IGNIL implements cmov/masks as arithmetic rather than preserving an
      // LLVM SelectInst. A mapped concrete upper half is a cheap pointer gate;
      // enumerate only here, not on ordinary symbolic arguments/data values.
      if (!recognized) {
        const auto upper = normalized.extract(63, 32).simplify();
        if (upper.is_numeral() && state_.hasMemoryPrefix(upper.get_numeral_uint64())) {
          bool exhaustive = false;
          auto values = enumerate(normalized, 2, &exhaustive);
          if (exhaustive && values.size() == 2) {
            arms.clear();
            for (auto v : values) {
              const auto literal = bvVal(*ctx_, v, 64);
              arms.push_back({normalized == literal, literal});
            }
            recognized = true;
          }
        }
      }
      if (recognized && !z3::eq(arms[0].value, arms[1].value) &&
          state_.isMemoryDefined(arms[0].value.get_numeral_uint64(), 8) &&
          state_.isMemoryDefined(arms[1].value.get_numeral_uint64(), 8)) {
        MemoryReadChoice choice{true, op.address, candidates->front(), 0, *op.dst, normalized, {}, {}};
        for (const auto &a : arms) {
          const auto feasible = isSatisfiable(a.guard);
          if (feasible && !*feasible) continue;
          choice.values.push_back(a.value.get_numeral_uint64());
          choice.guards.push_back(a.guard);
        }
        if (choice.values.size() == 1) {
          chooseMemoryRead(choice, 0);
          return ExecStatus::Ok;
        }
        if (choice.values.size() > 1) {
          result.memoryChoice = std::move(choice);
          return ExecStatus::Ok;
        }
      }
    }
    writeDst(*op.dst, value);
    return ExecStatus::Ok;
  }

  // STORE: srcs[0] = address, srcs[1] = value, no dst.
  if (op.srcs.size() != 2)
    return ExecStatus::MalformedOp;

  const z3::expr addr = eval(op.srcs[0]).simplify();
  const Width width = widthOf(op.srcs[1]);
  const z3::expr value = zeroCoerce(eval(op.srcs[1]), width);

  auto candidates = concretize(addr, opts_.maxAddressSolutions, op,
                               "store address", result);
  if (!candidates) {
    // Refusing to guess: the store is dropped and the caller is told, rather
    // than silently corrupting an address that only looked plausible.
    result.unresolved.push_back(
            {/*isStore=*/true, op.address, width, addr, value});
    return ExecStatus::Ok;
  }

  if (candidates->size() == 1) {
    state_.writeMemory(candidates->front(), value);
    return ExecStatus::Ok;
  }

  // Several possible addresses: write every one conditionally, so each byte
  // keeps its old value on the paths where this store did not target it.
  const std::uint64_t n = byteCount(width);
  for (std::uint64_t target : *candidates) {
    const z3::expr hits = (addr == bvVal(*ctx_, target, bvWidth(addr)));
    for (std::uint64_t i = 0; i < n; ++i) {
      const z3::expr fresh =
              zeroCoerce(value, static_cast<Width>(n * 8))
                      .extract(static_cast<unsigned>(i * 8 + 7),
                               static_cast<unsigned>(i * 8));
      const z3::expr old = state_.readMemory(target + i, 8);
      state_.writeMemory(target + i, z3::ite(hits, fresh, old).simplify());
    }
  }
  return ExecStatus::Ok;
}

void SymbolicExecutor::addSuccessors(const z3::expr &target,
                                     const z3::expr &guard, bool taken,
                                     const Op &op, RunResult &result) {
  const z3::expr t = target.simplify();

  if (t.is_numeral()) {
    result.successors.push_back({t.get_numeral_uint64(), guard, taken});
    return;
  }

  auto candidates =
          concretize(t, opts_.maxBranchTargets, op, "branch target", result);
  if (!candidates) {
    // The edge exists but we cannot say where it goes. Recorded as a warning
    // so RunResult::complete() reports the successor list as partial.
    return;
  }

  for (std::uint64_t addr : *candidates) {
    const z3::expr reaches = (t == bvVal(*ctx_, addr, bvWidth(t)));
    result.successors.push_back({addr, (guard && reaches).simplify(), taken});
  }
}

z3::expr SymbolicExecutor::opaqueValue(const Op &op, Width dstWidth,
                                       RunResult &result) {
  const OpaqueKind kind = opaqueKindOf(op.aux);
  const unsigned index = opaqueIndexOf(op.aux);
  const std::string name(opaqueKindName(kind));

  std::vector<z3::expr> operands;
  for (const Value &v : op.srcs)
    operands.push_back(eval(v));
  // CPUID.01H enumerates processor signature/features using EAX only. ECX
  // is an output, not a subleaf selector for this leaf. Normalize only this
  // established leaf; indexed leaves (e.g. 07H) retain the exact ECX input.
  // This reuses a source-machine profile, never the analysis host's CPUID.
  if (kind == OpaqueKind::CPUID && operands.size() == 2) {
    const auto leaf = operands[0].simplify();
    if (leaf.is_numeral() && bvWidth(leaf) <= 64 &&
        leaf.get_numeral_uint64() == 1)
      operands[1] = bvVal(*ctx_, 0, bvWidth(operands[1]));
  }

  // Match caller-supplied results on the architecturally relevant operands.
  // An unknown relevant operand remains symbolic, rather than selecting a
  // solver model or falling back to analysis-host CPUID.
  bool explicitInvocation = false;
  if (!concreteOpaque_.empty()) {
    std::uint64_t selector = 0;
    bool matchable = true;
    for (std::size_t i = 0; i < operands.size() && i < 2; ++i) {
      const z3::expr s = operands[i].simplify();
      if (!s.is_numeral() || bvWidth(s) > 64) { matchable = false; break; }
      selector |= (s.get_numeral_uint64() & 0xffffffffULL) << (i == 0 ? 32 : 0);
    }
    if (matchable) {
      const auto it = concreteOpaque_.find({kind, selector});
      if (it != concreteOpaque_.end()) {
        explicitInvocation = true;
        if (index < it->second.size())
          return bvVal(*ctx_, it->second[index], dstWidth);
      }
    }
  }

  if (opts_.useHostTimestamps && !explicitInvocation &&
      (kind == OpaqueKind::RDTSC || kind == OpaqueKind::RDTSCP)) {
    auto &pending = result.pendingTimestamp_;
    const unsigned bit = 1u << index;
    // Repeated index means another dynamic execution, even at the same PC.
    // A high-only optimized instruction also starts a complete paired sample.
    if (!pending || pending->address != op.address || pending->kind != kind ||
        (result.timestampResultsSeen_ & bit)) {
      pending = readHostTimestamp(op, kind);
      result.timestampResultsSeen_ = 0;
      if (pending)
        result.hostTimestamps.push_back(*pending);
    }
    if (pending) {
      result.timestampResultsSeen_ |= bit;
      const std::uint64_t value = index == 0   ? (pending->tsc & 0xffffffffULL)
                                  : index == 1 ? (pending->tsc >> 32)
                                               : pending->aux;
      return bvVal(*ctx_, value, dstWidth);
    }
    warn(result, op,
         name + " unsupported on analysis host; result remains symbolic");
  }

  if (!opaqueIsPure(kind)) {
    // Each execution is its own event, so the symbol is keyed on where it
    // happened rather than on the operands: two RDTSCs never compare equal.
    return state_.symbol(
            name + "@" + hex(op.address) + "_" + std::to_string(index),
            dstWidth);
  }

  // Pure: an uninterpreted function of the operands, so two CPUIDs with the
  // same leaf and subleaf build the identical term and Z3 proves them equal.
  z3::expr_vector args(*ctx_);
  z3::sort_vector domain(*ctx_);
  for (const z3::expr &operand : operands) {
    args.push_back(operand);
    domain.push_back(args.back().get_sort());
  }
  const std::string fn = name + "." + std::to_string(index);
  return ctx_->function(fn.c_str(), domain, ctx_->bv_sort(dstWidth))(args);
}

ExecStatus SymbolicExecutor::stepBranch(const Op &op, RunResult &result) {
  switch (op.opcode) {
    case Opcode::JMP:
    case Opcode::CALL: {
      if (op.srcs.size() != 1)
        return ExecStatus::MalformedOp;
      result.exit = op.opcode == Opcode::JMP ? ExitKind::Jump : ExitKind::Call;
      addSuccessors(eval(op.srcs[0]), ctx_->bool_val(true), true, op, result);
      return ExecStatus::Ok;
    }

    case Opcode::RET:
      result.exit = ExitKind::Return;
      return ExecStatus::Ok;

    default: break; // CJMP
  }

  // CJMP: srcs[0] = condition, srcs[1] = taken target, srcs[2] = fallthrough.
  if (op.srcs.size() != 3)
    return ExecStatus::MalformedOp;

  result.exit = ExitKind::ConditionalJump;

  const z3::expr cond = eval(op.srcs[0]);
  const z3::expr isTrue = (cond != bvVal(*ctx_, 0, bvWidth(cond))).simplify();
  const z3::expr isFalse = (!isTrue).simplify();

  // Each side is only a real edge if the condition can hold there. This is
  // what collapses an opaque predicate to a single successor, and what prunes
  // a branch the accumulated path constraints have already decided.
  const std::pair<const z3::expr &, bool> sides[] = {{isTrue, true},
                                                     {isFalse, false}};
  const Value *targets[] = {&op.srcs[1], &op.srcs[2]};

  for (int i = 0; i < 2; ++i) {
    const auto &[guard, taken] = sides[i];
    // A guard that folded to a literal - the branch of a concrete run - is
    // decided already; isSatisfiable answers it without the solver, so it is
    // not counted as a query either.
    if (guard.is_false())
      continue;
    if (!(guard.is_true() && (state_.constraints().empty() ||
                              satisfiableConstraints_ == state_.constraints().size())))
      ++result.stats.solverQueries;
    const auto feasible = isSatisfiable(guard);

    if (!feasible) {
      // Unknown, not proven infeasible. Keeping the edge is the conservative
      // choice for CFG recovery: a lost edge hides code, a spurious one only
      // costs analysis time.
      warn(result, op,
           std::string("solver could not decide the ") +
                   (taken ? "taken" : "not-taken") +
                   " branch; edge kept without proof");
    } else if (!*feasible) {
      continue;
    }

    addSuccessors(eval(*targets[i]), guard, taken, op, result);
  }

  return ExecStatus::Ok;
}

ExecStatus SymbolicExecutor::step(const Op &op, RunResult &result) {
  if (result.pendingTimestamp_ &&
      result.pendingTimestamp_->address != op.address) {
    result.pendingTimestamp_.reset();
    result.timestampResultsSeen_ = 0;
  }
  switch (op.opcode) {
    case Opcode::LOAD:
    case Opcode::STORE:
      return stepMemory(op, result);

    case Opcode::JMP:
    case Opcode::CJMP:
    case Opcode::CALL:
    case Opcode::RET:
      return stepBranch(op, result);

    case Opcode::OPAQUE: {
      state_.invalidateCallTraces();
      if (!op.dst || std::holds_alternative<Const>(*op.dst))
        return ExecStatus::MalformedOp;
      if (opaqueIndexOf(op.aux) >= opaqueResultCount(opaqueKindOf(op.aux)))
        return ExecStatus::MalformedOp;
      writeDst(*op.dst, opaqueValue(op, widthOf(*op.dst), result));
      return ExecStatus::Ok;
    }

    case Opcode::UNDEF: {
      state_.invalidateCallTraces();
      if (!op.dst || std::holds_alternative<Const>(*op.dst))
        return ExecStatus::MalformedOp;
      // Different defs at one native PC are independent unknowns (notably
      // the two XMM banks). Address alone falsely equates their values, and
      // can even reuse a symbol of a different bit width. Honor the same
      // caller-supplied context tag as unresolved loads.
      const auto location =
              std::holds_alternative<Reg>(*op.dst)
                      ? "r" + std::to_string(std::get<Reg>(*op.dst).offset)
                      : "t" + std::to_string(std::get<Temp>(*op.dst).id);
      const auto width = widthOf(*op.dst);
      writeDst(*op.dst,
               state_.symbol("undef@" + hex(op.address) + "_" + location +
                                     "_w" + std::to_string(width) + "_" +
                                     std::to_string(result.stats.opsExecuted) +
                                     (freshTag_.empty() ? "" : "#" + freshTag_),
                             width));
      return ExecStatus::Ok;
    }

    default:
      break;
  }

  if (!op.dst || std::holds_alternative<Const>(*op.dst))
    return ExecStatus::MalformedOp;

  const Width dstWidth = widthOf(*op.dst);

  switch (op.opcode) {
    // Unary.
    case Opcode::COPY:
    case Opcode::NEG:
    case Opcode::NOT:
    case Opcode::ZEXT:
    case Opcode::SEXT:
    case Opcode::TRUNC:
    case Opcode::SITOFP:
    case Opcode::FPTOSI: {
      if (op.srcs.size() != 1)
        return ExecStatus::MalformedOp;
      const z3::expr src = eval(op.srcs[0]);
      const z3::expr value = unary(op.opcode, src, dstWidth);
      // Z3 builds the term it is asked for and folds nothing until told to,
      // so an op on a literal has to be folded here or a concrete run grows a
      // term per instruction that some later query then has to take apart.
      writeDst(*op.dst, src.is_numeral() ? value.simplify() : fold::local(value));
      return ExecStatus::Ok;
    }

    // Binary.
    case Opcode::ADD:
    case Opcode::SUB:
    case Opcode::MUL:
    case Opcode::SDIV:
    case Opcode::UDIV:
    case Opcode::SMOD:
    case Opcode::UMOD:
    case Opcode::AND:
    case Opcode::OR:
    case Opcode::XOR:
    case Opcode::SHL:
    case Opcode::SHR:
    case Opcode::SAR:
    case Opcode::EQ:
    case Opcode::NEQ:
    case Opcode::ULT:
    case Opcode::ULE:
    case Opcode::UGT:
    case Opcode::UGE:
    case Opcode::SLT:
    case Opcode::SLE:
    case Opcode::SGT:
    case Opcode::SGE:
    case Opcode::FADD:
    case Opcode::FSUB:
    case Opcode::FMUL:
    case Opcode::FDIV: {
      if (op.srcs.size() != 2)
        return ExecStatus::MalformedOp;
      const z3::expr lhs = eval(op.srcs[0]);
      const z3::expr rhs = eval(op.srcs[1]);
      const z3::expr value = binary(op.opcode, lhs, rhs, dstWidth);
      // binary() folds the newly built operation before its width adaptor;
      // do not traverse the same symbolic cone a second time here.
      writeDst(*op.dst, lhs.is_numeral() && rhs.is_numeral() ? value.simplify()
                                                             : value);
      return ExecStatus::Ok;
    }

    default:
      return ExecStatus::UnsupportedOp;
  }
}

RunResult SymbolicExecutor::run(const Block &block) { return runFrom(block, 0); }

RunResult SymbolicExecutor::runFrom(const Block &block, std::size_t firstOp) {
  if (!block.unlifted().empty()) state_.invalidateCallTraces();
  if (auto *effects = state_.memoryEffects(); effects && !block.unlifted().empty()) {
    effects->invalidate();
    RunResult result;
    result.ownedContext_ = ownedCtx_;
    result.status = ExecStatus::UnsupportedOp;
    result.exit = ExitKind::Error;
    result.error = "effect recovery rejects unlifted instruction at " + hex(block.unlifted().front());
    return result;
  }
  return runFrom(block.ops(), firstOp);
}

RunResult SymbolicExecutor::run(const std::vector<Op> &ops) { return runFrom(ops, 0); }

RunResult SymbolicExecutor::runFrom(const std::vector<Op> &ops,
                                    std::size_t firstOp) {
  RunResult result;
  result.ownedContext_ = ownedCtx_;

  for (std::size_t i = firstOp; i < ops.size(); ++i) {
    const Op &op = ops[i];
    const ExecStatus status = step(op, result);
    if (result.memoryChoice) {
      result.memoryChoice->nextOp = i + 1;
      return result;
    }
    ++result.stats.opsExecuted;

    if (status != ExecStatus::Ok) {
      state_.invalidateCallTraces();
      if (auto *effects = state_.memoryEffects())
        effects->invalidate();
      result.status = status;
      result.exit = ExitKind::Error;
      result.error =
              std::string(status == ExecStatus::MalformedOp ? "malformed "
                                                            : "unsupported ") +
              std::string(opcodeName(op.opcode)) + " op at " + hex(op.address);
      return result;
    }

    const bool terminator =
            op.opcode == Opcode::JMP || op.opcode == Opcode::CJMP ||
            op.opcode == Opcode::CALL || op.opcode == Opcode::RET;
    if (terminator && opts_.stopAtTerminator)
      break;
  }

  if (!result.warnings.empty() || !result.unresolved.empty()) {
    state_.invalidateCallTraces();
    if (auto *effects = state_.memoryEffects())
      effects->invalidate();
  }
  return result;
}

} // namespace dragon::ignil
