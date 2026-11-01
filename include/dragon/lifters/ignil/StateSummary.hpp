#pragma once

#include <dragon/lifters/ignil/StateAccess.hpp>
#include <memory>
#include <z3++.h>

namespace dragon::ignil {
class SymbolicState;

/// A deterministic, fixed-layout state transformer recovered from a fully
/// explored invocation. Read inputs are the union of path-local
/// read-before-write bytes; writes include every written byte, even if
/// unchanged. Its projection and input-domain queries must be independently
/// proved before application. Opaque/undefined observations are deliberately
/// excluded.
class StateSummary {
  public:
  struct Input {
    StateRange range;
    z3::expr actual, formal;
    bool control;
  };
  struct Output {
    StateRange range;
    z3::expr value;
  };
  StateSummary(const SymbolicState &before, const SymbolicState &after,
               StateAccessTrace &trace, std::uint64_t returnSlot,
               std::string_view tag, const z3::expr_vector &from,
               const z3::expr_vector &to);
  z3::expr projectionViolation() const { return projection_; }
  /// Current constraints AND NOT(exists source inputs matching current reads).
  /// Proving this UNSAT establishes coverage, including input correlations.
  z3::expr applicabilityViolation(const SymbolicState &current) const;
  /// Caller must prove the queries above; no current state may change between
  /// applicability and apply. Writes are parallel evaluations of input state.
  void apply(SymbolicState &current) const;
  const auto &inputs() const { return inputs_; }
  const auto &outputs() const { return outputs_; }

  private:
  std::shared_ptr<const SymbolicState> before_;
  std::vector<Input> inputs_;
  std::vector<Output> outputs_;
  z3::expr domain_, projection_;
  void compatible(const SymbolicState &) const;
};
} // namespace dragon::ignil
