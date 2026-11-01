#include <dragon/lifters/ignil/StateSummary.hpp>
#include <dragon/lifters/ignil/SymbolicExecutor.hpp>
#include <set>
#include <stdexcept>

namespace dragon::ignil {
namespace {
z3::expr normalized(z3::expr term, const z3::expr_vector &from,
                    const z3::expr_vector &to) {
  for (unsigned i = 0; i <= from.size(); ++i) {
    auto next = term.substitute(from, to);
    if (z3::eq(term, next))
      return next.simplify();
    term = next;
  }
  throw std::invalid_argument("cyclic summary normalization");
}
z3::expr_vector constants(const z3::expr &term) {
  z3::expr_vector result(term.ctx());
  std::set<unsigned> visited;
  std::vector<z3::expr> pending{term};
  while (!pending.empty()) {
    auto node = pending.back();
    pending.pop_back();
    if (!visited.insert(node.id()).second || node.is_var())
      continue;
    if (node.is_quantifier()) {
      pending.push_back(node.body());
      continue;
    }
    if (node.is_const() && node.decl().decl_kind() == Z3_OP_UNINTERPRETED)
      result.push_back(node);
    else if (node.is_app() && node.decl().decl_kind() == Z3_OP_UNINTERPRETED)
      throw std::invalid_argument(
              "summary contains an uninterpreted observation");
    for (unsigned i = 0; i < node.num_args(); ++i)
      pending.push_back(node.arg(i));
  }
  return result;
}
std::vector<StateRange> ranges(const std::vector<StateAccessTrace::Byte> &rows,
                               unsigned flag, std::uint64_t slot) {
  std::vector<StateRange> result;
  for (const auto &row: rows) {
    if (!(row.flags & flag))
      continue;
    if (flag == StateAccessTrace::EntryControlRead && row.memory &&
        row.key - slot < 8)
      continue; // Only RET control reads of the invocation's own return slot.
    if (!result.empty() && result.back().memory == row.memory &&
        result.back().key + result.back().bytes == row.key &&
        result.back().bytes < 8)
      ++result.back().bytes;
    else
      result.push_back({row.memory, row.key, 1});
  }
  return result;
}
} // namespace
StateSummary::StateSummary(const SymbolicState &before,
                           const SymbolicState &after, StateAccessTrace &trace,
                           std::uint64_t returnSlot, std::string_view tag,
                           const z3::expr_vector &from,
                           const z3::expr_vector &to) :
    before_(std::make_shared<SymbolicState>(before)),
    domain_(before.ctx().bool_val(true)),
    projection_(before.ctx().bool_val(false)) {
  compatible(after);
  if (!trace.complete() || !trace.cacheable() || !trace.hasExits())
    throw std::invalid_argument(
            "incomplete footprint/returns or opaque/undefined observation");
  const auto rows = trace.finish();
  for (const auto &row: rows)
    if (row.memory && row.key - returnSlot < 8 &&
        (row.flags & StateAccessTrace::Written))
      throw std::invalid_argument("callee writes its return slot");
  z3::expr_vector domain(before.ctx()), old(before.ctx()), formal(before.ctx());
  for (const auto &constraint: before.constraints_)
    domain.push_back(normalized(constraint, from, to));
  domain_ = z3::mk_and(domain);
  auto reads = ranges(rows,
                      StateAccessTrace::EntryRead | StateAccessTrace::Preserved,
                      returnSlot);
  const auto dataReads = reads.size();
  auto control = ranges(rows, StateAccessTrace::EntryControlRead, returnSlot);
  reads.insert(reads.end(), control.begin(), control.end());
  std::set<unsigned> replaced;
  auto add = [&](const z3::expr &actual, const z3::expr &parameter) {
    if (!actual.is_numeral() && replaced.insert(actual.id()).second) {
      old.push_back(actual);
      formal.push_back(parameter);
    }
  };
  for (const auto &range: reads) {
    auto actual = normalized(before.readRange(range), from, to);
    const auto width = static_cast<unsigned>(range.bytes * 8);
    const auto name = "summary." + std::string(tag) + ".input." +
                      std::to_string(inputs_.size());
    auto parameter = z3::expr(before.ctx(),
                              Z3_mk_fresh_const(before.ctx(), name.c_str(),
                                                before.ctx().bv_sort(width)));
    const bool isControl = inputs_.size() >= dataReads;
    inputs_.push_back({range, actual, parameter, isControl});
    // Entry operands may already be arithmetic expressions of outer arguments.
    // Undo only exact, width-preserving bijections; never solve for a model.
    auto value = actual;
    auto replacement = parameter;
    for (;;) {
      add(value, replacement);
      for (unsigned bits = width; bits > 0; --bits)
        add(value.extract(bits - 1, 0).simplify(),
            replacement.extract(bits - 1, 0));
      for (unsigned low = 8; low < width; low += 8)
        add(value.extract(low + 7, low).simplify(),
            replacement.extract(low + 7, low));
      const auto kind = value.decl().decl_kind();
      if (kind == Z3_OP_BNEG || kind == Z3_OP_BNOT) {
        replacement = kind == Z3_OP_BNEG ? -replacement : ~replacement;
        value = value.arg(0);
      } else if (kind == Z3_OP_BADD || kind == Z3_OP_BXOR) {
        unsigned symbolic = 0, index = 0;
        auto literal = before.ctx().bv_val(0, width);
        for (unsigned i = 0; i < value.num_args(); ++i) {
          if (!value.arg(i).is_numeral()) {
            ++symbolic;
            index = i;
          } else
            literal = kind == Z3_OP_BADD ? literal + value.arg(i)
                                         : literal ^ value.arg(i);
        }
        if (symbolic != 1)
          break;
        replacement = kind == Z3_OP_BADD ? replacement - literal
                                         : replacement ^ literal;
        value = value.arg(index);
      } else if (kind == Z3_OP_BSUB && value.arg(1).is_numeral()) {
        replacement = replacement + value.arg(1);
        value = value.arg(0);
      } else if (kind == Z3_OP_BSUB && value.arg(0).is_numeral()) {
        replacement = value.arg(0) - replacement;
        value = value.arg(1);
      } else
        break;
      replacement = replacement.simplify();
    }
  }
  std::set<unsigned> allowed;
  z3::expr_vector backFrom(before.ctx()), backTo(before.ctx());
  for (const auto &input: inputs_) {
    allowed.insert(input.formal.id());
    backFrom.push_back(input.formal);
    backTo.push_back(input.actual);
  }
  for (const auto &range: ranges(rows, StateAccessTrace::Written, returnSlot)) {
    auto actual = normalized(after.readRange(range), from, to);
    auto body = actual.substitute(old, formal).simplify();
    body = body.substitute(old, formal).simplify();
    for (const auto &dep: constants(body))
      if (!allowed.contains(dep.id()))
        throw std::invalid_argument(
                "state output retains a non-input dependency: " +
                dep.to_string() + " in " +
                (range.memory ? "memory " : "register ") +
                std::to_string(range.key));
    outputs_.push_back({range, body});
    auto reconstructed = body.substitute(backFrom, backTo);
    projection_ = projection_ || (reconstructed != actual);
  }
  projection_ = domain_ && projection_;
}
void StateSummary::compatible(const SymbolicState &current) const {
  const auto &before = *before_;
  if (&current.ctx() != &before.ctx() || current.memoryEffects_ ||
      before.memoryEffects_ || current.accessTrace_ || before.accessTrace_ ||
      current.opts_.symbolizeUnmappedReads !=
              before.opts_.symbolizeUnmappedReads ||
      current.opts_.zeroExtendOn32BitWrite !=
              before.opts_.zeroExtendOn32BitWrite ||
      current.images_.size() != before.images_.size())
    throw std::invalid_argument(
            "summary requires ordinary states with shared image backing");
  for (std::size_t i = 0; i < before.images_.size(); ++i)
    if (before.images_[i].base != current.images_[i].base ||
        before.images_[i].bytes != current.images_[i].bytes)
      throw std::invalid_argument("summary image backing changed");
}
z3::expr
StateSummary::applicabilityViolation(const SymbolicState &current) const {
  compatible(current);
  auto relation = domain_;
  for (const auto &input: inputs_)
    relation = relation && (input.actual == input.formal);
  auto variables = constants(relation);
  // Formal inputs are free here, source-context constants are existential.
  std::set<unsigned> formals;
  for (const auto &input: inputs_)
    formals.insert(input.formal.id());
  z3::expr_vector bound(current.ctx()), source(current.ctx()),
          from(current.ctx()), to(current.ctx());
  for (const auto &variable: variables) {
    if (formals.contains(variable.id()))
      continue;
    source.push_back(variable);
    bound.push_back(z3::expr(current.ctx(),
                             Z3_mk_fresh_const(current.ctx(), "summary.source",
                                               variable.get_sort())));
  }
  // Distinct binder names also preserve meaning through the C/Python SMT-LIB
  // bridge: current free roots must never be printed with a source binder name.
  relation = relation.substitute(source, bound);
  if (!bound.empty())
    relation = z3::exists(bound, relation);
  for (const auto &input: inputs_) {
    from.push_back(input.formal);
    to.push_back(current.readRange(input.range));
  }
  relation = relation.substitute(from, to);
  z3::expr_vector assumptions(current.ctx());
  for (const auto &c: current.constraints_)
    assumptions.push_back(c);
  return z3::mk_and(assumptions) && !relation;
}
void StateSummary::apply(SymbolicState &current) const {
  compatible(current);
  z3::expr_vector from(current.ctx()), to(current.ctx());
  for (const auto &input: inputs_) {
    from.push_back(input.formal);
    to.push_back(current.readRange(input.range));
  }
  std::vector<z3::expr> outputs;
  for (const auto &output: outputs_) {
    auto value = output.value;
    outputs.push_back(value.substitute(from, to).simplify());
  }
  for (const auto &input: inputs_)
    current.observeCallAccess(input.range.memory, input.range.key,
                              input.range.bytes, false, input.control);
  for (std::size_t i = 0; i < outputs_.size(); ++i) {
    const auto &range = outputs_[i].range;
    current.observeCallAccess(range.memory, range.key, range.bytes, true);
    current.writeRange(range, outputs[i]);
  }
  current.temps_.clear();
}
} // namespace dragon::ignil
