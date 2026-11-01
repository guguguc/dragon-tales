#include <dragon/lifters/ignil/IGNILSimplify.hpp>

#include <algorithm>
#include <cstdint>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>

namespace dragon::ignil {

namespace {

// ---------------------------------------------------------------------------
// Width-aware integer helpers
// ---------------------------------------------------------------------------

std::uint64_t maskTo(std::uint64_t v, Width w) {
  if (w >= 64)
    return v;
  return v & ((std::uint64_t{1} << w) - 1);
}

std::int64_t signExtend(std::uint64_t v, Width w) {
  if (w >= 64)
    return static_cast<std::int64_t>(v);
  std::uint64_t masked = maskTo(v, w);
  std::uint64_t signBit = std::uint64_t{1} << (w - 1);
  if (masked & signBit)
    masked |= ~((std::uint64_t{1} << w) - 1);
  return static_cast<std::int64_t>(masked);
}

/// A Const carries 64 bits of value, so one wider than 64 bits (the 128-bit
/// dividend of a 64-bit DIV) cannot be all-ones, and folding at that width
/// with uint64_t arithmetic would be wrong: such ops are left to Z3 / LLVM.
constexpr Width kMaxFoldWidth = 64;

bool isAllOnes(const Const &c) {
  if (c.width > kMaxFoldWidth)
    return false;
  return maskTo(c.value, c.width) == maskTo(~std::uint64_t{0}, c.width);
}

bool isZero(const Const &c) { return maskTo(c.value, c.width) == 0; }

// ---------------------------------------------------------------------------
// Constant folding
// ---------------------------------------------------------------------------

bool isBinaryFoldable(Opcode op) {
  switch (op) {
    case Opcode::ADD:
    case Opcode::SUB:
    case Opcode::MUL:
    case Opcode::AND:
    case Opcode::OR:
    case Opcode::XOR:
    case Opcode::SHL:
    case Opcode::SHR:
    case Opcode::SAR:
    case Opcode::SDIV:
    case Opcode::UDIV:
    case Opcode::SMOD:
    case Opcode::UMOD:
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

bool isUnaryFoldable(Opcode op) {
  switch (op) {
    case Opcode::NEG:
    case Opcode::NOT:
    case Opcode::ZEXT:
    case Opcode::SEXT:
    case Opcode::TRUNC:
      return true;
    default:
      return false;
  }
}

// dstWidth == 0 means "no dst / use operand width" (never hit for the
// opcodes handled here in well-formed IGNIL - ADD/SUB/... always have a
// dst - but treated defensively rather than assumed).
std::optional<Const> foldBinary(Opcode op, const Const &l, const Const &r,
                                Width dstWidth) {
  if (l.width > kMaxFoldWidth || r.width > kMaxFoldWidth || dstWidth > kMaxFoldWidth)
    return std::nullopt;
  // Comparisons always produce a 1-bit result, independent of operand width.
  {
    std::uint64_t lv = maskTo(l.value, l.width);
    std::uint64_t rv = maskTo(r.value, r.width);
    std::int64_t ls = signExtend(l.value, l.width);
    std::int64_t rs = signExtend(r.value, r.width);
    switch (op) {
      case Opcode::EQ: return Const{lv == rv ? 1u : 0u, 1};
      case Opcode::NEQ: return Const{lv != rv ? 1u : 0u, 1};
      case Opcode::ULT: return Const{lv < rv ? 1u : 0u, 1};
      case Opcode::ULE: return Const{lv <= rv ? 1u : 0u, 1};
      case Opcode::UGT: return Const{lv > rv ? 1u : 0u, 1};
      case Opcode::UGE: return Const{lv >= rv ? 1u : 0u, 1};
      case Opcode::SLT: return Const{ls < rs ? 1u : 0u, 1};
      case Opcode::SLE: return Const{ls <= rs ? 1u : 0u, 1};
      case Opcode::SGT: return Const{ls > rs ? 1u : 0u, 1};
      case Opcode::SGE: return Const{ls >= rs ? 1u : 0u, 1};
      default: break;
    }
  }

  Width w = dstWidth ? dstWidth : std::max(l.width, r.width);
  std::uint64_t lv = maskTo(l.value, l.width);
  std::uint64_t rv = maskTo(r.value, r.width);
  std::int64_t ls = signExtend(l.value, l.width);
  std::int64_t rs = signExtend(r.value, r.width);
  // Raw (unmasked-to-w) shift amount - a shift count stored in a narrower
  // Const than the shifted value is still a valid amount to compare to w.
  std::uint64_t shiftAmount = maskTo(r.value, r.width);

  switch (op) {
    case Opcode::ADD: return Const{maskTo(lv + rv, w), w};
    case Opcode::SUB: return Const{maskTo(lv - rv, w), w};
    case Opcode::MUL: return Const{maskTo(lv * rv, w), w};
    case Opcode::AND: return Const{maskTo(lv & rv, w), w};
    case Opcode::OR: return Const{maskTo(lv | rv, w), w};
    case Opcode::XOR: return Const{maskTo(lv ^ rv, w), w};
    case Opcode::SHL:
      return Const{shiftAmount >= w ? 0 : maskTo(lv << shiftAmount, w), w};
    case Opcode::SHR:
      return Const{shiftAmount >= w ? 0 : maskTo(lv >> shiftAmount, w), w};
    case Opcode::SAR: {
      if (shiftAmount >= w)
        return Const{ls < 0 ? maskTo(~std::uint64_t{0}, w) : 0, w};
      return Const{maskTo(static_cast<std::uint64_t>(ls >> shiftAmount), w),
                   w};
    }
    // Division/modulo by zero: leave unfolded rather than guessing trap
    // semantics IGNIL doesn't model.
    case Opcode::UDIV:
      return rv == 0 ? std::nullopt
                      : std::optional<Const>{Const{maskTo(lv / rv, w), w}};
    case Opcode::SDIV:
      return rs == 0 ? std::nullopt
                      : std::optional<Const>{Const{
                                maskTo(static_cast<std::uint64_t>(ls / rs), w),
                                w}};
    case Opcode::UMOD:
      return rv == 0 ? std::nullopt
                      : std::optional<Const>{Const{maskTo(lv % rv, w), w}};
    case Opcode::SMOD:
      return rs == 0 ? std::nullopt
                      : std::optional<Const>{Const{
                                maskTo(static_cast<std::uint64_t>(ls % rs), w),
                                w}};
    default:
      return std::nullopt;
  }
}

std::optional<Const> foldUnary(Opcode op, const Const &v, Width dstWidth) {
  if (v.width > kMaxFoldWidth || dstWidth > kMaxFoldWidth)
    return std::nullopt;
  std::uint64_t vv = maskTo(v.value, v.width);
  switch (op) {
    case Opcode::NEG:
      return Const{maskTo(static_cast<std::uint64_t>(-static_cast<std::int64_t>(vv)),
                          v.width),
                   v.width};
    case Opcode::NOT:
      return Const{maskTo(~vv, v.width), v.width};
    case Opcode::ZEXT: {
      Width dw = dstWidth ? dstWidth : v.width;
      return Const{maskTo(vv, dw), dw};
    }
    case Opcode::SEXT: {
      Width dw = dstWidth ? dstWidth : v.width;
      return Const{maskTo(static_cast<std::uint64_t>(signExtend(v.value, v.width)),
                          dw),
                   dw};
    }
    case Opcode::TRUNC: {
      Width dw = dstWidth ? dstWidth : v.width;
      return Const{maskTo(vv, dw), dw};
    }
    default:
      return std::nullopt;
  }
}

bool allConst(const std::vector<Value> &srcs) {
  return std::all_of(srcs.begin(), srcs.end(), [](const Value &v) {
    return std::holds_alternative<Const>(v);
  });
}

Op copyOfConst(const std::optional<Value> &dst, Const c, std::uint64_t addr) {
  Op o;
  o.opcode = Opcode::COPY;
  o.dst = dst;
  o.srcs = {Value{c}};
  o.address = addr;
  return o;
}

// ---------------------------------------------------------------------------
// Algebraic identity / annihilator elimination - exactly one of {lhs, rhs}
// is a literal Const, the other is left symbolic. Requires matching operand
// widths (same-width ALU semantics - IGNIL never mixes widths on a single
// ADD/AND/OR/... without an explicit ZEXT/SEXT/TRUNC first).
// ---------------------------------------------------------------------------

std::optional<Op> tryIdentity(Opcode op, const Value &lhs, const Value &rhs,
                              const std::optional<Value> &dst,
                              std::uint64_t addr) {
  const auto *cl = std::get_if<Const>(&lhs);
  const auto *cr = std::get_if<Const>(&rhs);
  if (static_cast<bool>(cl) == static_cast<bool>(cr))
    return std::nullopt; // need exactly one const side

  if (widthOf(lhs) != widthOf(rhs))
    return std::nullopt;
  Width w = widthOf(lhs);

  auto asCopy = [&](Value v) {
    Op o;
    o.opcode = Opcode::COPY;
    o.dst = dst;
    o.srcs = {std::move(v)};
    o.address = addr;
    return o;
  };
  auto asCopyConst = [&](std::uint64_t val) {
    return asCopy(Value{Const{maskTo(val, w), w}});
  };

  if (cl) {
    // Const <op> rhs
    const Const &c = *cl;
    switch (op) {
      case Opcode::ADD:
        if (isZero(c)) return asCopy(rhs);
        break;
      case Opcode::AND:
        if (isAllOnes(c)) return asCopy(rhs);
        if (isZero(c)) return asCopyConst(0);
        break;
      case Opcode::OR:
        if (isZero(c)) return asCopy(rhs);
        if (isAllOnes(c)) return asCopyConst(~std::uint64_t{0});
        break;
      case Opcode::XOR:
        if (isZero(c)) return asCopy(rhs);
        break;
      case Opcode::MUL:
        if (c.value == 1) return asCopy(rhs);
        if (isZero(c)) return asCopyConst(0);
        break;
      default:
        break;
    }
  } else {
    // lhs <op> Const
    const Const &c = *cr;
    switch (op) {
      case Opcode::ADD:
      case Opcode::SUB:
        if (isZero(c)) return asCopy(lhs);
        break;
      case Opcode::AND:
        if (isAllOnes(c)) return asCopy(lhs);
        if (isZero(c)) return asCopyConst(0);
        break;
      case Opcode::OR:
        if (isZero(c)) return asCopy(lhs);
        if (isAllOnes(c)) return asCopyConst(~std::uint64_t{0});
        break;
      case Opcode::XOR:
        if (isZero(c)) return asCopy(lhs);
        break;
      case Opcode::MUL:
        if (c.value == 1) return asCopy(lhs);
        if (isZero(c)) return asCopyConst(0);
        break;
      case Opcode::SHL:
      case Opcode::SHR:
      case Opcode::SAR:
        if (isZero(c)) return asCopy(lhs);
        break;
      default:
        break;
    }
  }
  return std::nullopt;
}

bool sameValue(const Value &a, const Value &b) {
  if (a.index() != b.index())
    return false;
  return std::visit(
          [&](const auto &av) {
            using T = std::decay_t<decltype(av)>;
            const auto &bv = std::get<T>(b);
            if constexpr (std::is_same_v<T, Const>)
              return av.width == bv.width &&
                     maskTo(av.value, av.width) == maskTo(bv.value, bv.width);
            else if constexpr (std::is_same_v<T, Reg>)
              return av.offset == bv.offset && av.width == bv.width;
            else // Temp
              return av.id == bv.id && av.width == bv.width;
          },
          a);
}

// ---------------------------------------------------------------------------
// Half-adder identity: `dst = ADD(XOR(p,q), 2*AND(p,q))` -> `dst = ADD(p,q)`.
// The "2*" step is matched as either `SHL(and, 1)` or `ADD(and, and)` (the
// same value added to itself) - real lifted code from x86 tends to use the
// latter (`add eax, eax` for a x2 rather than `shl eax, 1`), and both are
// semantically identical doubling.
//
// This is a well-known, general algebraic identity (the textbook "sum =
// XOR, carry = AND, doubled-carry + sum = full sum" decomposition), not a
// VM-specific pattern - it shows up in ordinary bit-trick code too, not just
// MBA-obfuscated VM handlers. Verified empirically (opt-21 -O3 on a minimal
// repro) that LLVM's InstCombine does NOT fold this on its own, unlike the
// closely related `(a|b)-(a^b) -> a&b` and `a+(-b) -> a-b`, which it does.
// `defOf` is the current (already-substituted) single definition of each
// Temp seen so far in this forward pass - safe to trust because Temps are
// single-assignment within a block.
// ---------------------------------------------------------------------------

std::optional<Op> tryHalfAdderIdentity(
        const Op &op, const std::unordered_map<std::uint32_t, Op> &defOf) {
  if (op.opcode != Opcode::ADD || op.srcs.size() != 2)
    return std::nullopt;

  auto getDef = [&](const Value &v) -> const Op * {
    const auto *t = std::get_if<Temp>(&v);
    if (!t)
      return nullptr;
    auto it = defOf.find(t->id);
    return it == defOf.end() ? nullptr : &it->second;
  };

  auto matchXor = [&](const Value &v, Value &p, Value &q) {
    const Op *d = getDef(v);
    if (!d || d->opcode != Opcode::XOR || d->srcs.size() != 2)
      return false;
    p = d->srcs[0];
    q = d->srcs[1];
    return true;
  };

  auto matchDoubledAnd = [&](const Value &v, Value &p, Value &q) {
    const Op *d = getDef(v);
    if (!d)
      return false;
    const Op *andDef = nullptr;
    if (d->opcode == Opcode::SHL && d->srcs.size() == 2) {
      const auto *shAmt = std::get_if<Const>(&d->srcs[1]);
      if (!shAmt || maskTo(shAmt->value, shAmt->width) != 1)
        return false;
      andDef = getDef(d->srcs[0]);
    } else if (d->opcode == Opcode::ADD && d->srcs.size() == 2 &&
               sameValue(d->srcs[0], d->srcs[1])) {
      andDef = getDef(d->srcs[0]);
    } else {
      return false;
    }
    if (!andDef || andDef->opcode != Opcode::AND || andDef->srcs.size() != 2)
      return false;
    p = andDef->srcs[0];
    q = andDef->srcs[1];
    return true;
  };

  for (bool swapped: {false, true}) {
    const Value &xorSide = swapped ? op.srcs[1] : op.srcs[0];
    const Value &doubledSide = swapped ? op.srcs[0] : op.srcs[1];
    Value xp, xq, ap, aq;
    if (!matchXor(xorSide, xp, xq) || !matchDoubledAnd(doubledSide, ap, aq))
      continue;
    bool sameOrder = sameValue(xp, ap) && sameValue(xq, aq);
    bool swappedOrder = sameValue(xp, aq) && sameValue(xq, ap);
    if (!sameOrder && !swappedOrder)
      continue;
    Op rewritten;
    rewritten.opcode = Opcode::ADD;
    rewritten.dst = op.dst;
    rewritten.srcs = {xp, xq};
    rewritten.address = op.address;
    return rewritten;
  }
  return std::nullopt;
}

bool hasSideEffect(Opcode op) {
  switch (op) {
    case Opcode::STORE:
    case Opcode::JMP:
    case Opcode::CJMP:
    case Opcode::CALL:
    case Opcode::RET:
      return true;
    default:
      // Includes LOAD: IGNIL has no volatile/side-effecting LOAD, so an
      // unused load result is as removable as any other pure Temp def.
      return false;
  }
}

// ---------------------------------------------------------------------------
// Forward pass: constant fold + propagate (Temps only - Reg is not
// guaranteed single-assignment within a block, so it is deliberately not
// tracked here) + algebraic identities + no-op width conversions.
// ---------------------------------------------------------------------------

Block passForward(const Block &in, SimplifyStats &stats) {
  Block out{in.startAddress()};
  for (std::uint64_t address : in.unlifted())
    out.noteUnlifted(address);
  // Records `t = COPY(v)` so later uses of `t` substitute `v` directly -
  // general copy propagation, not just constant propagation: `v` may be a
  // Const, a Reg, or another (already-resolved) Temp. Temp-only, since Temps
  // are the only IGNIL value guaranteed single-assignment within a block
  // (same invariant BackwardSlicer::sliceValue relies on for Temps vs Reg).
  std::unordered_map<std::uint32_t, Value> copyOf;
  // Records the current (already-substituted/rewritten) defining Op of every
  // Temp seen so far - e.g. `t = NEG(x)` so a later NEG(t)/NOT(t) collapses
  // to COPY(x), or `t = XOR(p,q)` so a later ADD(t, ...) can be checked
  // against the half-adder identity below. Same Temp-only reasoning as
  // copyOf - only Temps are guaranteed single-assignment in a block.
  std::unordered_map<std::uint32_t, Op> defOf;

  auto substitute = [&](const Value &v) -> Value {
    if (const auto *t = std::get_if<Temp>(&v)) {
      auto it = copyOf.find(t->id);
      if (it != copyOf.end())
        return it->second;
    }
    return v;
  };

  for (const Op &op: in) {
    Op newOp = op;
    for (auto &s: newOp.srcs)
      s = substitute(s);

    bool handled = false;
    Width dstWidth = newOp.dst ? widthOf(*newOp.dst) : Width{0};

    if (allConst(newOp.srcs)) {
      if (newOp.srcs.size() == 1 && isUnaryFoldable(newOp.opcode)) {
        if (auto folded = foldUnary(newOp.opcode, std::get<Const>(newOp.srcs[0]),
                                    dstWidth)) {
          newOp = copyOfConst(newOp.dst, *folded, newOp.address);
          handled = true;
          ++stats.constantsFolded;
        }
      } else if (newOp.srcs.size() == 2 && isBinaryFoldable(newOp.opcode)) {
        if (auto folded = foldBinary(newOp.opcode, std::get<Const>(newOp.srcs[0]),
                                     std::get<Const>(newOp.srcs[1]), dstWidth)) {
          newOp = copyOfConst(newOp.dst, *folded, newOp.address);
          handled = true;
          ++stats.constantsFolded;
        }
      }
    }

    if (!handled && newOp.srcs.size() == 2) {
      if (auto rw = tryIdentity(newOp.opcode, newOp.srcs[0], newOp.srcs[1],
                                newOp.dst, newOp.address)) {
        newOp = std::move(*rw);
        handled = true;
        ++stats.identitiesApplied;
      }
    }

    if (!handled && newOp.srcs.size() == 1 &&
        (newOp.opcode == Opcode::NEG || newOp.opcode == Opcode::NOT)) {
      if (const auto *t = std::get_if<Temp>(&newOp.srcs[0])) {
        auto it = defOf.find(t->id);
        if (it != defOf.end() && it->second.opcode == newOp.opcode &&
            it->second.srcs.size() == 1 && newOp.dst &&
            widthOf(it->second.srcs[0]) == widthOf(*newOp.dst)) {
          newOp.opcode = Opcode::COPY;
          newOp.srcs = {it->second.srcs[0]};
          handled = true;
          ++stats.identitiesApplied;
        }
      }
    }

    if (!handled && newOp.srcs.size() == 1 &&
        (newOp.opcode == Opcode::ZEXT || newOp.opcode == Opcode::SEXT ||
         newOp.opcode == Opcode::TRUNC) &&
        newOp.dst && widthOf(newOp.srcs[0]) == widthOf(*newOp.dst)) {
      newOp.opcode = Opcode::COPY;
      handled = true;
      ++stats.identitiesApplied;
    }

    if (!handled) {
      if (auto rw = tryHalfAdderIdentity(newOp, defOf)) {
        newOp = std::move(*rw);
        handled = true;
        ++stats.identitiesApplied;
      }
    }

    // A Reg write invalidates every record that refers to that Reg. The Temp
    // a record is keyed on is single-assignment, but the Reg it was copied
    // from is not: once something overwrites that Reg, substituting a later
    // use of the Temp with it would read the *new* value. `xchg` is the
    // canonical victim (t0 = COPY(EAX); EAX = COPY(t1); ECX = COPY(t0) would
    // collapse to ECX = COPY(EAX), i.e. no swap at all), and any lifter that
    // snapshots a register it then overwrites hits the same thing.
    // Sub-register aliasing counts, so the test is on overlapping byte ranges.
    if (newOp.dst) {
      if (const auto *dr = std::get_if<Reg>(&*newOp.dst)) {
        const std::uint64_t lo = dr->offset;
        const std::uint64_t hi = lo + (dr->width + 7u) / 8u;
        auto overlaps = [&](const Value &v) {
          const auto *r = std::get_if<Reg>(&v);
          if (!r)
            return false;
          const std::uint64_t rlo = r->offset;
          const std::uint64_t rhi = rlo + (r->width + 7u) / 8u;
          return rlo < hi && lo < rhi;
        };
        std::erase_if(copyOf, [&](const auto &e) { return overlaps(e.second); });
        std::erase_if(defOf, [&](const auto &e) {
          return std::any_of(e.second.srcs.begin(), e.second.srcs.end(),
                             overlaps);
        });
      }
    }

    if (newOp.dst) {
      if (const auto *dt = std::get_if<Temp>(&*newOp.dst)) {
        copyOf.erase(dt->id);
        defOf.erase(dt->id);
        if (newOp.opcode == Opcode::COPY && newOp.srcs.size() == 1)
          copyOf.emplace(dt->id, newOp.srcs[0]);
        // Recorded for every opcode, regardless of operand kind (Reg or
        // Temp) - it's dt->id (a Temp, guaranteed single-assignment) that
        // makes this record safe to trust later. Lookups above restrict
        // which shapes/operand-kinds they actually collapse on.
        defOf.emplace(dt->id, newOp);
      }
    }

    out.append(std::move(newOp));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Backward pass: drop Temp-defining ops whose result is never read later in
// the block. Reg-defining ops are always kept - a Reg may be live-out across
// the block boundary, which this block-local pass cannot see.
// ---------------------------------------------------------------------------

Block passBackwardDCE(const Block &in, SimplifyStats &stats) {
  const std::vector<Op> &ops = in.ops();
  std::unordered_set<std::uint32_t> usedTemps;
  std::vector<bool> keep(ops.size(), true);

  for (std::size_t i = ops.size(); i-- > 0;) {
    const Op &op = ops[i];
    bool dead = false;
    if (op.dst && !hasSideEffect(op.opcode)) {
      if (const auto *t = std::get_if<Temp>(&*op.dst))
        dead = !usedTemps.count(t->id);
    }
    if (dead) {
      keep[i] = false;
      ++stats.opsRemoved;
      continue; // dropped - its own srcs don't count as uses
    }
    for (const auto &s: op.srcs) {
      if (const auto *t = std::get_if<Temp>(&s))
        usedTemps.insert(t->id);
    }
  }

  Block out{in.startAddress()};
  for (std::uint64_t address : in.unlifted())
    out.noteUnlifted(address);
  for (std::size_t i = 0; i < ops.size(); ++i)
    if (keep[i])
      out.append(ops[i]);
  return out;
}

// ---------------------------------------------------------------------------
// Dead-store elimination: byte-precise backward register/flag liveness.
//
// Generalizes passBackwardDCE from Temps to architectural Regs. The register
// address space is a flat byte array (see IGNIL.hpp / x86registers.def), so
// overlapping sub-registers (RAX/EAX/AX/AL, AH) alias by byte and flags are
// ordinary single bytes. One backward pass is exact for straight-line code:
// a removed store's sources are not counted as uses, so a whole dead chain
// collapses without needing a fixed point.
// ---------------------------------------------------------------------------

// Parent size assumed for a 32-bit write when no register file is supplied.
// Exact for x86-64 GPRs (EAX -> RAX) and AArch64 W registers (W0 -> X0); see
// DeadStoreOptions::registerFile for when that assumption is not enough.
constexpr std::uint32_t kAssumedParentBytes = 8;

// Bytes actually read when `r` is a source: exactly its own width, never
// zero-extended (reading EAX reads bytes [0,4), not RAX[4,8)).
std::uint32_t readByteCount(const Reg &r) {
  return (static_cast<std::uint32_t>(r.width) + 7u) / 8u;
}

// Bytes from `r`'s offset to the end of the maximal register containing it, or
// 0 if the register file does not describe one. Sub-registers share their
// parent's base offset in this model (EAX/RAX at 0, S0/V0 at 272), with
// AH-style high bytes sitting inside it, so containment - not equality - is the
// test, and the count runs from r.offset rather than the parent's so a view
// that does not start at the base still stops exactly at the parent's end.
std::uint32_t bytesToParentEnd(const std::vector<RegExtent> &regFile,
                               const Reg &r) {
  const std::uint32_t own = readByteCount(r);
  for (const RegExtent &p: regFile)
    if (p.offset <= r.offset && r.offset + own <= p.offset + p.byteSize)
      return p.offset + p.byteSize - r.offset;
  return 0;
}

// Bytes clobbered by writing `r`. width bits -> ceil(width/8) bytes at
// [offset, offset+n). Under the zero-extend rule a 32-bit write also clears the
// rest of its parent, so it clobbers the parent's *whole* extent: EAX kills
// RAX[0,8), W0 kills X0[0,8), and S0 kills V0[0,16) - the AArch64 case an
// 8-byte assumption gets wrong. Since a store is dropped only when every byte
// it clobbers is dead, under-estimating this range is what would let a write
// whose upper parent bytes are live be removed.
std::uint32_t clobberByteCount(const Reg &r, const DeadStoreOptions &opts) {
  const std::uint32_t own = readByteCount(r);
  if (!opts.zeroExtendOn32BitWrite || r.width != 32)
    return own;
  if (std::uint32_t toParentEnd = bytesToParentEnd(opts.registerFile, r))
    return toParentEnd;
  return std::max(own, kAssumedParentBytes);
}

void insertBytes(std::unordered_set<std::uint32_t> &set, std::uint32_t offset,
                 std::uint32_t count) {
  for (std::uint32_t b = 0; b < count; ++b)
    set.insert(offset + b);
}

Block passRegDSE(const Block &in,
                 const std::optional<std::vector<Reg>> &liveOut,
                 const DeadStoreOptions &opts, SimplifyStats &stats) {
  const std::vector<Op> &ops = in.ops();

  std::unordered_set<std::uint32_t> liveBytes; // live register-space bytes
  std::unordered_set<std::uint32_t> liveTemps; // live temp ids

  if (liveOut) {
    for (const Reg &r: *liveOut)
      insertBytes(liveBytes, r.offset, readByteCount(r));
  } else {
    // "assume everything live on exit": seed with every register byte the
    // block mentions. A byte never mentioned cannot be defined here, so its
    // liveness is irrelevant; every byte that *is* defined starts live, so a
    // store is removable only once overwritten later in the block before any
    // read. This is Triton's block-DSE model and needs no ABI knowledge.
    for (const Op &op: ops) {
      if (op.dst)
        if (const auto *r = std::get_if<Reg>(&*op.dst))
          insertBytes(liveBytes, r->offset,
                      clobberByteCount(*r, opts));
      for (const auto &s: op.srcs)
        if (const auto *r = std::get_if<Reg>(&s))
          insertBytes(liveBytes, r->offset, readByteCount(*r));
    }
  }

  auto anyByteLive = [&](std::uint32_t offset, std::uint32_t count) {
    for (std::uint32_t b = 0; b < count; ++b)
      if (liveBytes.count(offset + b))
        return true;
    return false;
  };

  std::vector<bool> keep(ops.size(), true);

  for (std::size_t i = ops.size(); i-- > 0;) {
    const Op &op = ops[i];

    bool removable = false;
    if (op.dst && !hasSideEffect(op.opcode)) {
      if (const auto *r = std::get_if<Reg>(&*op.dst))
        removable = !anyByteLive(
                r->offset, clobberByteCount(*r, opts));
      else if (const auto *t = std::get_if<Temp>(&*op.dst))
        removable = !liveTemps.count(t->id);
    }

    if (removable) {
      keep[i] = false;
      ++stats.opsRemoved;
      continue; // dropped: its sources do not count as uses
    }

    // Kept: kill the bytes/temp this op defines, then mark its reads live.
    // Kill-before-add keeps a read-modify-write (dst also a src, e.g.
    // ADD rax, rbx) live, since the src re-adds it.
    if (op.dst) {
      if (const auto *r = std::get_if<Reg>(&*op.dst)) {
        std::uint32_t n = clobberByteCount(*r, opts);
        for (std::uint32_t b = 0; b < n; ++b)
          liveBytes.erase(r->offset + b);
      } else if (const auto *t = std::get_if<Temp>(&*op.dst)) {
        liveTemps.erase(t->id);
      }
    }
    for (const auto &s: op.srcs) {
      if (const auto *r = std::get_if<Reg>(&s))
        insertBytes(liveBytes, r->offset, readByteCount(*r));
      else if (const auto *t = std::get_if<Temp>(&s))
        liveTemps.insert(t->id);
    }
  }

  Block out{in.startAddress()};
  for (std::uint64_t address : in.unlifted())
    out.noteUnlifted(address);
  for (std::size_t i = 0; i < ops.size(); ++i)
    if (keep[i])
      out.append(ops[i]);
  return out;
}

} // namespace

Block simplifyBlock(const Block &block, SimplifyStats &stats,
                    int maxIterations) {
  stats = SimplifyStats{};
  Block current = block;
  for (int iter = 0; iter < maxIterations; ++iter) {
    SimplifyStats iterStats;
    Block afterForward = passForward(current, iterStats);
    Block afterDCE = passBackwardDCE(afterForward, iterStats);

    stats.constantsFolded += iterStats.constantsFolded;
    stats.identitiesApplied += iterStats.identitiesApplied;
    stats.opsRemoved += iterStats.opsRemoved;
    stats.iterations = iter + 1;

    current = std::move(afterDCE);
    if (!iterStats.changed())
      break;
  }
  return current;
}

Block simplifyBlock(const Block &block, int maxIterations) {
  SimplifyStats stats;
  return simplifyBlock(block, stats, maxIterations);
}

Block deadStoreEliminate(const Block &block,
                         const std::optional<std::vector<Reg>> &liveOut,
                         SimplifyStats &stats, DeadStoreOptions opts) {
  stats = SimplifyStats{};
  Block out = passRegDSE(block, liveOut, opts, stats);
  stats.iterations = 1; // exact in a single backward pass
  return out;
}

Block deadStoreEliminate(const Block &block,
                         const std::optional<std::vector<Reg>> &liveOut,
                         DeadStoreOptions opts) {
  SimplifyStats stats;
  return deadStoreEliminate(block, liveOut, stats, opts);
}

} // namespace dragon::ignil
