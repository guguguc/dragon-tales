#pragma once

#include <z3++.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

// Construction-time identities only. Operands are already execution-state
// values: never recursively simplify their entire history or ask a solver.
namespace dragon::ignil::fold {
inline unsigned width(const z3::expr &e) { return e.get_sort().bv_size(); }
inline bool kind(const z3::expr &e, Z3_decl_kind k) {
  return e.is_app() && e.decl().decl_kind() == k;
}
inline bool zero(const z3::expr &e) {
  return e.is_numeral() &&
         std::string(Z3_get_numeral_string(e.ctx(), e)) == "0";
}
inline bool ones(const z3::expr &e) {
  return e.is_numeral() && z3::eq(e, (~e.ctx().bv_val(0, width(e))).simplify());
}
inline bool complement(const z3::expr &a, const z3::expr &b) {
  return (kind(a, Z3_OP_BNOT) && z3::eq(a.arg(0), b)) ||
         (kind(b, Z3_OP_BNOT) && z3::eq(b.arg(0), a));
}
inline z3::expr local(const z3::expr &e, unsigned fuel = 12);
inline z3::expr slice(const z3::expr &e, unsigned hi, unsigned lo,
                      unsigned fuel = 12);
inline z3::expr concat(const z3::expr &hi, const z3::expr &lo,
                       unsigned fuel = 12);

inline z3::expr slice(const z3::expr &e, unsigned hi, unsigned lo,
                      unsigned fuel) {
  if (!lo && hi + 1 == width(e))
    return e;
  if (!fuel)
    return e.extract(hi, lo);
  if (e.is_numeral())
    return e.extract(hi, lo).simplify();
  if (kind(e, Z3_OP_EXTRACT))
    return slice(e.arg(0), e.lo() + hi, e.lo() + lo, fuel - 1);
  if (kind(e, Z3_OP_ZERO_EXT)) {
    const auto w = width(e.arg(0));
    if (lo >= w)
      return e.ctx().bv_val(0, hi - lo + 1);
    if (hi < w)
      return slice(e.arg(0), hi, lo, fuel - 1);
    return concat(e.ctx().bv_val(0, hi - w + 1),
                  slice(e.arg(0), w - 1, lo, fuel - 1), fuel - 1);
  }
  if (kind(e, Z3_OP_CONCAT)) {
    // Project only the overlapping spans; a partial read need not build a
    // concatenation of every original byte and then simplify that entire DAG.
    std::optional<z3::expr> result;
    unsigned end = width(e);
    for (unsigned i = 0; i < e.num_args(); ++i) {
      const auto a = e.arg(i);
      const unsigned begin = end - width(a);
      if (lo < end && hi >= begin) {
        auto part = slice(a, std::min(hi, end - 1) - begin,
                          std::max(lo, begin) - begin, fuel - 1);
        result = result ? concat(*result, part, fuel - 1) : part;
      }
      end = begin;
    }
    return *result;
  }
  return e.extract(hi, lo);
}

inline z3::expr concat(const z3::expr &hi, const z3::expr &lo, unsigned fuel) {
  if (!fuel)
    return z3::concat(hi, lo);
  if (hi.is_numeral() && lo.is_numeral())
    return z3::concat(hi, lo).simplify();
  const auto highSource = kind(hi, Z3_OP_EXTRACT) ? hi.arg(0) : hi;
  const auto lowSource = kind(lo, Z3_OP_EXTRACT) ? lo.arg(0) : lo;
  const unsigned highOffset = kind(hi, Z3_OP_EXTRACT) ? hi.lo() : 0;
  const unsigned lowOffset = kind(lo, Z3_OP_EXTRACT) ? lo.lo() : 0;
  if (z3::eq(highSource, lowSource) && highOffset == lowOffset + width(lo))
    return slice(highSource, highOffset + width(hi) - 1, lowOffset, fuel - 1);
  // Recover whole bitwise values from byte/word pieces. This factors, rather
  // than distributes, operations and does not assume anything about inputs.
  const auto k = hi.decl().decl_kind();
  if (k == lo.decl().decl_kind()) {
    if (k == Z3_OP_BNOT)
      return local(~concat(hi.arg(0), lo.arg(0), fuel - 1), fuel - 1);
    if ((k == Z3_OP_BXOR || k == Z3_OP_BOR || k == Z3_OP_BAND) &&
        hi.num_args() == 2 && lo.num_args() == 2) {
      auto a = concat(hi.arg(0), lo.arg(0), fuel - 1);
      auto b = concat(hi.arg(1), lo.arg(1), fuel - 1);
      return local(k == Z3_OP_BXOR  ? a ^ b
                   : k == Z3_OP_BOR ? a | b
                                    : a & b,
                   fuel - 1);
    }
  }
  // Merge the touching boundary of an already assembled span.
  if (kind(lo, Z3_OP_CONCAT) && lo.num_args() == 2)
    return concat(concat(hi, lo.arg(0), fuel - 1), lo.arg(1), fuel - 1);
  if (kind(hi, Z3_OP_CONCAT) && hi.num_args() == 2)
    return z3::concat(hi.arg(0), concat(hi.arg(1), lo, fuel - 1));
  if (zero(hi))
    return local(z3::zext(lo, width(hi)), fuel - 1);
  return z3::concat(hi, lo);
}

// Exact local Boolean-cone folding, with word-sized leaves. The 64-bit
// table covers EVERY assignment to up to six abstract input bits, not sampled
// program inputs. Since only bitwise gates are traversed, an identity holds
// independently in every bit lane. Arithmetic, shifts and prior XOR values
// remain opaque leaves, preserving word-level structure between operations.
inline std::optional<z3::expr> affineGate(const z3::expr &root) {
  constexpr std::uint64_t patterns[] = {
          0xaaaaaaaaaaaaaaaaULL, 0xccccccccccccccccULL, 0xf0f0f0f0f0f0f0f0ULL,
          0xff00ff00ff00ff00ULL, 0xffff0000ffff0000ULL, 0xffffffff00000000ULL};
  std::vector<z3::expr> leaves;
  std::unordered_map<unsigned, std::uint64_t> memo;
  unsigned remaining = 32;
  std::function<std::optional<std::uint64_t>(const z3::expr &, unsigned)> visit;
  visit = [&](const z3::expr &e,
              unsigned depth) -> std::optional<std::uint64_t> {
    if (auto it = memo.find(e.id()); it != memo.end())
      return it->second;
    if (zero(e))
      return 0;
    if (ones(e))
      return ~std::uint64_t{0};
    const auto k = e.decl().decl_kind();
    const bool gate = k == Z3_OP_BAND || k == Z3_OP_BOR || k == Z3_OP_BNOT;
    std::uint64_t value;
    if (gate && depth && remaining) {
      --remaining;
      auto first = visit(e.arg(0), depth - 1);
      if (!first)
        return std::nullopt;
      value = k == Z3_OP_BNOT ? ~*first : *first;
      for (unsigned i = 1; i < e.num_args(); ++i) {
        auto next = visit(e.arg(i), depth - 1);
        if (!next)
          return std::nullopt;
        value = k == Z3_OP_BAND ? value & *next : value | *next;
      }
    } else {
      if (leaves.size() == 6)
        return std::nullopt;
      value = patterns[leaves.size()];
      leaves.push_back(e);
    }
    memo.emplace(e.id(), value);
    return value;
  };
  auto table = visit(root, 6);
  if (!table)
    return std::nullopt;
  const bool invert = (*table & 1) != 0;
  std::uint64_t affine = invert ? ~std::uint64_t{0} : 0;
  std::vector<unsigned> selected;
  for (unsigned i = 0; i < leaves.size(); ++i)
    if (((*table >> (1u << i)) & 1) != invert) {
      selected.push_back(i);
      affine ^= patterns[i];
    }
  if (affine != *table)
    return std::nullopt;
  z3::expr result = root.ctx().bv_val(0, width(root));
  if (!selected.empty()) {
    result = leaves[selected.front()];
    for (unsigned i = 1; i < selected.size(); ++i)
      result = result ^ leaves[selected[i]];
  }
  if (selected.empty())
    return invert ? (~result).simplify() : result;
  return invert ? ~result : result;
}

inline z3::expr local(const z3::expr &e, unsigned fuel) {
  if (!fuel || !e.is_app() || !e.num_args())
    return e;
  const auto k = e.decl().decl_kind();
  if (k == Z3_OP_EXTRACT)
    return slice(e.arg(0), e.hi(), e.lo(), fuel - 1);
  if (k == Z3_OP_CONCAT && e.num_args() == 2)
    return concat(e.arg(0), e.arg(1), fuel - 1);
  if (k == Z3_OP_ZERO_EXT) {
    const auto a = e.arg(0);
    if (a.is_numeral())
      return e.simplify();
    if (kind(a, Z3_OP_ZERO_EXT))
      return z3::zext(a.arg(0), width(e) - width(a.arg(0)));
    return e;
  }
  if (k == Z3_OP_BNOT) {
    const auto a = e.arg(0);
    if (a.is_numeral())
      return e.simplify();
    if (kind(a, Z3_OP_BNOT))
      return a.arg(0);
    if (kind(a, Z3_OP_BAND) || kind(a, Z3_OP_BOR))
      if (auto folded = affineGate(e))
        return *folded;
    return e;
  }
  if (k == Z3_OP_ITE) {
    const auto c = e.arg(0), a = e.arg(1), b = e.arg(2);
    if (c.is_true() || z3::eq(a, b))
      return a;
    if (c.is_false())
      return b;
    return e;
  }
  if (e.num_args() != 2 || !e.arg(0).is_bv() || !e.arg(1).is_bv())
    return e;
  const auto a = e.arg(0), b = e.arg(1);
  if (a.is_numeral() && b.is_numeral())
    return e.simplify();
  const bool same = z3::eq(a, b);
  const auto constant = [&](bool all) {
    auto v = a.ctx().bv_val(0, width(a));
    return all ? (~v).simplify() : v;
  };
  switch (k) {
    case Z3_OP_BADD:
      if (zero(a))
        return b;
      if (zero(b))
        return a;
      break;
    case Z3_OP_BSUB:
      if (same)
        return constant(false);
      if (zero(b))
        return a;
      break;
    case Z3_OP_BXOR:
      if (same)
        return constant(false);
      if (complement(a, b))
        return constant(true);
      if (zero(a))
        return b;
      if (zero(b))
        return a;
      if (ones(a))
        return local(~b, fuel - 1);
      if (ones(b))
        return local(~a, fuel - 1);
      if (kind(a, Z3_OP_BNOT) && kind(b, Z3_OP_BNOT))
        return local(a.arg(0) ^ b.arg(0), fuel - 1);
      if (kind(a, Z3_OP_BNOT))
        return local(~local(a.arg(0) ^ b, fuel - 1), fuel - 1);
      if (kind(b, Z3_OP_BNOT))
        return local(~local(a ^ b.arg(0), fuel - 1), fuel - 1);
      break;
    case Z3_OP_BAND:
    case Z3_OP_BOR: {
      const bool isAnd = k == Z3_OP_BAND;
      if (same)
        return a;
      if (complement(a, b))
        return constant(!isAnd);
      if (zero(a))
        return isAnd ? a : b;
      if (zero(b))
        return isAnd ? b : a;
      if (ones(a))
        return isAnd ? b : a;
      if (ones(b))
        return isAnd ? a : b;
      // (x & ~y) | (~x & y), and its dual, are XOR. Match while
      // x/y are still word-sized, before any bit-vector decomposition.
      const auto inner = isAnd ? Z3_OP_BOR : Z3_OP_BAND;
      const auto pair =
              [&](const z3::expr &v) -> std::optional<std::array<z3::expr, 2>> {
        if (kind(v, inner) && v.num_args() == 2)
          return std::array<z3::expr, 2>{v.arg(0), v.arg(1)};
        // Z3 canonicalizes x & y to ~(~x | ~y). Recognize that
        // representation too; LOAD normalization must not hide XOR patterns.
        const auto dual = inner == Z3_OP_BAND ? Z3_OP_BOR : Z3_OP_BAND;
        if (kind(v, Z3_OP_BNOT) && kind(v.arg(0), dual) &&
            v.arg(0).num_args() == 2)
          return std::array<z3::expr, 2>{local(~v.arg(0).arg(0), fuel - 1),
                                         local(~v.arg(0).arg(1), fuel - 1)};
        return std::nullopt;
      };
      const auto av = pair(a), bv = pair(b);
      if (av && bv) {
        for (unsigned i = 0; i < 2; ++i)
          if (complement((*av)[0], (*bv)[i]) &&
              complement((*av)[1], (*bv)[1 - i])) {
            const auto v = local((*av)[0] ^ (*av)[1], fuel - 1);
            return isAnd ? v : local(~v, fuel - 1);
          }
      }
      const auto compound = [](const z3::expr &v) {
        return kind(v, Z3_OP_BAND) || kind(v, Z3_OP_BOR) ||
               (kind(v, Z3_OP_BNOT) &&
                (kind(v.arg(0), Z3_OP_BAND) || kind(v.arg(0), Z3_OP_BOR)));
      };
      if (compound(a) || compound(b))
        if (auto folded = affineGate(e))
          return *folded;
      break;
    }
    case Z3_OP_BSHL:
    case Z3_OP_BLSHR:
    case Z3_OP_BASHR:
      if (zero(b))
        return a;
      if (zero(a))
        return a;
      break;
    case Z3_OP_EQ:
    case Z3_OP_ULEQ:
    case Z3_OP_UGEQ:
    case Z3_OP_SLEQ:
    case Z3_OP_SGEQ:
      if (same)
        return e.ctx().bool_val(true);
      break;
    case Z3_OP_DISTINCT:
    case Z3_OP_ULT:
    case Z3_OP_UGT:
    case Z3_OP_SLT:
    case Z3_OP_SGT:
      if (same)
        return e.ctx().bool_val(false);
      break;
    default:
      break;
  }
  return e;
}
} // namespace dragon::ignil::fold
