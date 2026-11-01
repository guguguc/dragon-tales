#pragma once

#include <map>
#include <unordered_set>
#include "SymbolicFold.hpp"

namespace dragon::ignil::projection {
// Reconstruct small flag/selector results from predicates actually present in
// their DAG. This is not input sampling: each accepted bit formula is proved
// for the full explicit domain. Counterexample models only reject proposals.
// Data words are never bit-blasted into the returned expression.
template<class Check>
z3::expr bitPlanes(const z3::expr &root, const z3::expr &domain, Check check,
                   std::size_t &rewrites) {
  if (!root.is_bv() || fold::width(root) > 64)
    return root;
  const auto width = fold::width(root);
  const auto normalized =
          root.simplify(); // Discovery only; retain word payloads.
  unsigned bits = width;
  while (bits && fold::zero(normalized.extract(bits - 1, bits - 1).simplify()))
    --bits;
  if (!bits)
    return root;
  if (bits > 16) {
    z3::solver bound(root.ctx());
    bound.add(domain && (z3::lshr(normalized, 16) != 0));
    if (check(bound) != z3::unsat)
      return root;
    bits = 16;
  }

  const auto size = [](const z3::expr &value, unsigned limit = 16) {
    std::unordered_set<unsigned> seen;
    std::vector<z3::expr> pending{value};
    while (!pending.empty() && seen.size() <= limit) {
      const auto node = pending.back();
      pending.pop_back();
      if (!seen.insert(node.id()).second)
        continue;
      for (unsigned i = 0; i < node.num_args(); ++i)
        pending.push_back(node.arg(i));
    }
    return seen.size();
  };
  std::vector<z3::expr> atoms, pending{normalized};
  std::unordered_set<unsigned> seen, atomIds;
  const auto add = [&](const z3::expr &value) {
    auto candidate = value.simplify();
    if (size(candidate) <= 16 && atomIds.insert(candidate.id()).second)
      atoms.push_back(candidate);
  };
  while (!pending.empty()) {
    const auto node = pending.back();
    pending.pop_back();
    if (!seen.insert(node.id()).second)
      continue;
    if (node.is_bool() && node.num_args() == 2 && node.arg(0).is_bv() &&
        fold::width(node.arg(0)) >= 8 && size(node) <= 16) {
      add(node);
      const auto a = node.arg(0), b = node.arg(1);
      // Strict/non-strict comparisons share the same observed operands.
      switch (node.decl().decl_kind()) {
        case Z3_OP_ULEQ:
        case Z3_OP_ULT:
          add(z3::ult(a, b));
          add(z3::ule(a, b));
          break;
        case Z3_OP_SLEQ:
        case Z3_OP_SLT:
          add(a < b);
          add(a <= b);
          break;
        default:
          break;
      }
    }
    for (unsigned i = 0; i < node.num_args(); ++i)
      pending.push_back(node.arg(i));
  }
  std::stable_sort(atoms.begin(), atoms.end(),
                   [&](auto &a, auto &b) { return size(a) < size(b); });
  if (atoms.size() > 32)
    atoms.erase(atoms.begin() + 32, atoms.end());

  std::vector<z3::expr> candidates{root.ctx().bool_val(false),
                                   root.ctx().bool_val(true)};
  for (const auto &atom: atoms) {
    candidates.push_back(atom);
    candidates.push_back(!atom);
  }
  for (unsigned i = 0; i < atoms.size(); ++i)
    for (unsigned j = i + 1; j < atoms.size(); ++j) {
      candidates.push_back(atoms[i] != atoms[j]);
      candidates.push_back(atoms[i] == atoms[j]);
    }

  std::map<unsigned, std::pair<z3::expr, std::uint64_t>> planes;
  for (unsigned bit = 0; bit < bits; ++bit) {
    const auto target = (normalized.extract(bit, bit) == 1).simplify();
    std::vector<z3::model> counterexamples;
    bool found = false;
    for (const auto &candidate: candidates) {
      bool rejected = false;
      for (auto &model: counterexamples)
        if (model.eval(target != candidate, true).is_true()) {
          rejected = true;
          break;
        }
      if (rejected)
        continue;
      z3::solver solver(root.ctx());
      solver.add(domain && (target != candidate));
      const auto verdict = check(solver);
      if (verdict == z3::unknown)
        return root;
      if (verdict == z3::sat) {
        counterexamples.push_back(solver.get_model());
        continue;
      }
      const auto key = candidate.id();
      auto [where, inserted] =
              planes.emplace(key, std::make_pair(candidate, 0));
      where->second.second |= std::uint64_t(1) << bit;
      found = true;
      break;
    }
    if (!found)
      return root;
  }
  auto result = root.ctx().bv_val(0, width);
  for (const auto &[id, plane]: planes) {
    const auto &[condition, mask] = plane;
    if (!condition.is_false())
      result = fold::local(result |
                           z3::ite(condition, root.ctx().bv_val(mask, width),
                                   root.ctx().bv_val(0, width)));
  }
  // Do not turn an already-small selector into a larger mask assembly.
  if (size(result, 4096) >= size(root, 4096))
    return root;
  ++rewrites;
  return result;
}
} // namespace dragon::ignil::projection
