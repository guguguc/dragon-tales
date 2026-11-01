#include <algorithm>
#include <chrono>
#include <dragon/lifters/ignil/SymbolicExecutor.hpp>
#include <map>
#include <set>
#include <unordered_set>
#include "ProjectionBitPlanes.hpp"
#include "SymbolicFold.hpp"

namespace {
std::size_t cost(const z3::expr &root) {
  std::unordered_set<unsigned> seen;
  std::vector<z3::expr> pending{root};
  while (!pending.empty() && seen.size() < 4096) {
    const auto term = pending.back();
    pending.pop_back();
    if (!seen.insert(term.id()).second || !term.is_app())
      continue;
    for (unsigned i = 0; i < term.num_args(); ++i)
      pending.push_back(term.arg(i));
  }
  return seen.size();
}

z3::expr membership(const z3::expr &slice, const std::set<unsigned> &values) {
  auto &ctx = slice.ctx();
  const auto max = (1U << slice.get_sort().bv_size()) - 1;
  std::vector<std::pair<unsigned, unsigned>> runs;
  for (auto value: values) {
    if (!runs.empty() && runs.back().second + 1 == value)
      runs.back().second = value;
    else
      runs.emplace_back(value, value);
  }
  z3::expr result = ctx.bool_val(false);
  for (auto [first, last]: runs) {
    auto part = ctx.bool_val(true);
    if (first == last)
      part = slice == ctx.bv_val(first, slice.get_sort().bv_size());
    else {
      if (first)
        part = part &&
               z3::uge(slice, ctx.bv_val(first, slice.get_sort().bv_size()));
      if (last < max)
        part = part &&
               z3::ule(slice, ctx.bv_val(last, slice.get_sort().bv_size()));
    }
    result = result || part;
  }
  return result.simplify();
}
} // namespace

z3::expr dragon::ignil::SymbolicExecutor::simplifyProjection(
        const z3::expr &expression, const z3::expr &domain,
        const std::vector<z3::expr> &inputs, unsigned timeoutMs,
        std::size_t *queryCount, std::size_t *rewriteCount) const {
  if (&expression.ctx() != ctx_ || &domain.ctx() != ctx_ || !domain.is_bool())
    throw std::invalid_argument(
            "projection requires one context and boolean domain");
  for (const auto &input: inputs)
    if (&input.ctx() != ctx_ || !input.is_bv() || !input.is_const() ||
        input.decl().decl_kind() != Z3_OP_UNINTERPRETED)
      throw std::invalid_argument("projection inputs must be free bitvectors");
  const bool wholeDomain = domain.simplify().is_true();
  const auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(timeoutMs);
  std::size_t queries = 0, rewrites = 0;
  auto check = [&](z3::solver &solver) {
    const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now())
                    .count();
    if (remaining <= 0 || queries >= (wholeDomain ? 768U : 512U))
      return z3::unknown;
    solver.set("timeout",
               static_cast<unsigned>(std::min<std::int64_t>(remaining, 100)));
    ++queries;
    return solver.check();
  };
  // A model value is a proposal only. Keep it precisely when a second,
  // independent query proves the projection constant over the entire domain.
  if (expression.is_bv() && !expression.is_numeral()) {
    z3::solver constant(*ctx_);
    constant.add(domain);
    if (check(constant) == z3::sat) {
      const auto value = constant.get_model().eval(expression, true);
      if (value.is_numeral()) {
        constant.add(expression != value);
        if (check(constant) == z3::unsat) {
          if (queryCount)
            *queryCount = queries;
          if (rewriteCount)
            *rewriteCount = 1;
          return value;
        }
      }
    }
  }
  // A constrained projection can intentionally retain values outside its
  // domain for the subsequent all-input lowering proof. Preserve its existing
  // finite-guard strategy/shape; use the new canonicalizer for whole-domain
  // returns rather than changing those out-of-domain payloads incidentally.
  const unsigned wordQueryLimit = wholeDomain ? 256 : 512;
  auto projection = expression;
  std::vector<z3::expr> conditions, nodes, pending;
  const auto inspect = [&]() {
    conditions.clear();
    nodes.clear();
    std::unordered_set<unsigned> seen;
    if (!wholeDomain) {
      std::unordered_set<unsigned> conditionIds;
      std::vector<z3::expr> work{projection};
      if (projection.is_bool()) {
        conditions.push_back(projection);
        conditionIds.insert(projection.id());
      }
      while (!work.empty()) {
        auto term = work.back();
        work.pop_back();
        if (!seen.insert(term.id()).second)
          continue;
        if (!term.is_app() || seen.size() > 100000)
          return false;
        nodes.push_back(term);
        if (term.decl().decl_kind() == Z3_OP_ITE &&
            conditionIds.insert(term.arg(0).id()).second &&
            conditions.size() < 64)
          conditions.push_back(term.arg(0));
        for (unsigned i = 0; i < term.num_args(); ++i)
          work.push_back(term.arg(i));
      }
      return true;
    }
    std::vector<std::pair<z3::expr, bool>> traversal{{projection, false}};
    while (!traversal.empty()) {
      const auto [term, ready] = traversal.back();
      traversal.pop_back();
      if (ready) {
        nodes.push_back(term); // Own ASTs in child-before-parent order.
        // Include predicates inside BV returns and BV1 machine flags, not
        // only a Boolean root or the outermost ITE guards.
        if ((term.is_bool() ||
             (term.is_bv() && term.get_sort().bv_size() == 1)) &&
            !term.is_const() && conditions.size() < 128)
          conditions.push_back(term);
        continue;
      }
      if (!seen.insert(term.id()).second)
        continue;
      if (!term.is_app() || seen.size() > 100000)
        return false;
      traversal.emplace_back(term, true);
      for (unsigned i = 0; i < term.num_args(); ++i)
        traversal.emplace_back(term.arg(i), false);
    }
    return true;
  };
  const auto bounded = [&]() {
    if (queryCount)
      *queryCount = queries;
    if (rewriteCount)
      *rewriteCount = 0;
    return expression;
  };
  if (!inspect())
    return bounded();
  // Keep word payloads intact. Normalizing the complete return distributes
  // arithmetic/XOR through extracts and turns whole words into bit fragments.
  // Guards are normalized independently below, never their data payloads.
  // Projection inputs used only in payloads cannot explain a guard. Avoid
  // spending the shared solver budget on unrelated accumulator/pointer bits.
  std::unordered_set<unsigned> guardNodes;
  pending = conditions;
  while (!pending.empty()) {
    const auto term = pending.back();
    pending.pop_back();
    if (!guardNodes.insert(term.id()).second)
      continue;
    for (unsigned i = 0; i < term.num_args(); ++i)
      pending.push_back(term.arg(i));
  }
  std::vector<z3::expr> slices;
  std::unordered_set<unsigned> sliceIds;
  const auto addSlice = [&](const z3::expr &slice) {
    if (sliceIds.insert(slice.id()).second)
      slices.push_back(slice);
  };
  for (const auto &input: inputs) {
    if (!guardNodes.contains(input.id()))
      continue;
    const auto width = input.get_sort().bv_size();
    for (unsigned bits = 1; bits <= std::min(6U, width); ++bits)
      addSlice(input.extract(bits - 1, 0));
    addSlice(input.extract(width - 1, width - 1));
    // Other observed small slices are candidates too, not just low bits.
    for (const auto &node: nodes)
      if (node.decl().decl_kind() == Z3_OP_EXTRACT &&
          node.get_sort().bv_size() <= 6 && z3::eq(node.arg(0), input))
        addSlice(node);
  }
  z3::expr_vector from(*ctx_), to(*ctx_);
  // Machine flags often remain BV1 data (XOR, masks, concatenation) rather
  // than Boolean ITE guards. Prove their predicate, then restore their sort.
  const auto predicate = [&](const z3::expr &value) {
    return value.is_bool() ? value : value == ctx_->bv_val(1, 1);
  };
  const auto payload = [&](const z3::expr &original,
                           const z3::expr &condition) {
    return original.is_bool()
                   ? condition
                   : z3::ite(condition, ctx_->bv_val(1, 1), ctx_->bv_val(0, 1))
                             .simplify();
  };
  for (const auto &original: conditions) {
    if (!wholeDomain && !expression.is_bool())
      break;
    if (std::chrono::steady_clock::now() >= deadline ||
        queries >= wordQueryLimit)
      break;
    auto current = z3::expr(original).substitute(from, to).simplify();
    auto condition = predicate(current).simplify();
    if (condition.is_true() || condition.is_false()) {
      from.push_back(original);
      to.push_back(payload(original, condition));
      ++rewrites;
      continue;
    }
    if (cost(condition) < 8)
      continue;
    // Native flag/mask arithmetic can hide a simple whole-word predicate.
    // Propose only observed input slices and thresholds from the actual DAG;
    // a solver proof under the explicit domain is required for every rewrite.
    // This also handles a Boolean projection root, not only ITE conditions.
    bool replaced = false;
    {
      std::vector<z3::expr> localNodes, localPending{condition};
      std::unordered_set<unsigned> localIds;
      while (!localPending.empty()) {
        auto node = localPending.back();
        localPending.pop_back();
        if (!localIds.insert(node.id()).second)
          continue;
        localNodes.push_back(node);
        for (unsigned i = 0; i < node.num_args(); ++i)
          localPending.push_back(node.arg(i));
      }
      std::vector<z3::expr> words;
      std::unordered_set<unsigned> wordIds;
      for (const auto &input: inputs) {
        bool direct = false;
        for (const auto &node: localNodes) {
          if (node.decl().decl_kind() == Z3_OP_EXTRACT &&
              z3::eq(node.arg(0), input)) {
            if (node.get_sort().bv_size() > 6 &&
                wordIds.insert(node.id()).second)
              words.push_back(node);
          } else {
            for (unsigned i = 0; i < node.num_args(); ++i)
              direct |= z3::eq(node.arg(i), input);
          }
        }
        if (direct && wordIds.insert(input.id()).second)
          words.push_back(input);
      }
      // Counterexamples only reject proposals; only an UNSAT query accepts
      // one. Reusing them avoids proving hundreds of already-refuted guesses.
      std::vector<z3::model> counterexamples;
      const auto tryPredicate = [&](const z3::expr &candidate) {
        if (queries >= wordQueryLimit)
          return false;
        if (cost(payload(original, candidate)) >= cost(current))
          return false;
        for (auto &model: counterexamples)
          if (model.eval(condition != candidate, true).is_true())
            return false;
        z3::solver proof(*ctx_);
        proof.add(domain && (condition != candidate));
        const auto verdict = check(proof);
        if (verdict != z3::unsat) {
          if (verdict == z3::sat)
            counterexamples.push_back(proof.get_model());
          return false;
        }
        from.push_back(original);
        to.push_back(payload(original, candidate));
        ++rewrites;
        return true;
      };
      // Packed flags can encode one computed bit through wide arithmetic and
      // CONCATs. Cofactor observed one-bit cut points, not concrete program
      // inputs. Two constant cofactors cover the entire cut-point domain;
      // still require the independent predicate proof before replacing it.
      if (wholeDomain) {
        unsigned attempts = 0;
        for (const auto &atom: localNodes) {
          if (std::chrono::steady_clock::now() >= deadline || attempts >= 32)
            break;
          if (z3::eq(atom, condition) || atom.is_const() ||
              !(atom.is_bool() || (atom.is_bv() && fold::width(atom) == 1)))
            continue;
          ++attempts;
          z3::expr_vector source(*ctx_), low(*ctx_), high(*ctx_);
          source.push_back(atom);
          low.push_back(atom.is_bool() ? ctx_->bool_val(false) : ctx_->bv_val(0, 1));
          high.push_back(atom.is_bool() ? ctx_->bool_val(true) : ctx_->bv_val(1, 1));
          auto zero = z3::expr(condition).substitute(source, low).simplify();
          auto one = z3::expr(condition).substitute(source, high).simplify();
          if (!(zero.is_true() || zero.is_false()) ||
              !(one.is_true() || one.is_false()))
            continue;
          auto candidate = z3::ite(predicate(atom), one, zero).simplify();
          if (tryPredicate(candidate)) {
            replaced = true;
            break;
          }
        }
      }
      for (const auto &word: words) {
        if (replaced)
          break;
        const auto bits = word.get_sort().bv_size();
        if (bits > 64)
          continue;
        // Comparisons may have two symbolic input operands, not just an
        // input and a threshold. Keep the same proof and size requirements.
        if (wholeDomain) {
          for (const auto &other: words) {
            if (other.get_sort().bv_size() != bits || z3::eq(word, other))
              continue;
            for (const auto &candidate:
                 {word == other, z3::sle(word, other), z3::ule(word, other)}) {
              if (tryPredicate(candidate) || tryPredicate(!candidate)) {
                replaced = true;
                break;
              }
            }
            if (replaced || queries >= wordQueryLimit)
              break;
          }
          if (replaced)
            break;
        }
        const auto mask =
                bits == 64 ? ~std::uint64_t(0) : (std::uint64_t(1) << bits) - 1;
        std::set<std::uint64_t> thresholds{0};
        for (const auto &node: localNodes) {
          std::uint64_t literal;
          if (!node.is_bv() || node.get_sort().bv_size() != bits ||
              !node.is_numeral_u64(literal))
            continue;
          for (auto value: {literal, (~literal) & mask, (-literal) & mask})
            for (auto delta:
                 {std::uint64_t(-1), std::uint64_t(0), std::uint64_t(1)})
              thresholds.insert((value + delta) & mask);
        }
        std::vector<std::uint64_t> ordered(thresholds.begin(),
                                           thresholds.end());
        std::stable_sort(
                ordered.begin(), ordered.end(), [mask](auto a, auto b) {
                  return std::min(a, (-a) & mask) < std::min(b, (-b) & mask);
                });
        for (auto threshold: ordered) {
          if (std::chrono::steady_clock::now() >= deadline ||
              queries >= wordQueryLimit)
            break;
          const auto literal = ctx_->bv_val(threshold, bits);
          for (const auto &candidate: {word == literal, z3::sle(word, literal),
                                       z3::ule(word, literal)}) {
            if (tryPredicate(candidate) || tryPredicate(!candidate)) {
              replaced = true;
              break;
            }
          }
          if (replaced)
            break;
        }
        if (replaced)
          break;
      }
    }
  }
  // Preserve budget for finite selectors. Work from enclosing guards back to
  // their flag machinery, not through every internal flag before the guard.
  std::unordered_set<unsigned> rewritten;
  for (unsigned i = 0; i < from.size(); ++i)
    rewritten.insert(from[i].id());
  auto finiteConditions = conditions;
  if (wholeDomain)
    std::reverse(finiteConditions.begin(), finiteConditions.end());
  for (const auto &original: finiteConditions) {
    if (rewritten.contains(original.id()))
      continue;
    if (std::chrono::steady_clock::now() >= deadline || queries >= 512)
      break;
    auto current = z3::expr(original).substitute(from, to).simplify();
    auto condition = predicate(current).simplify();
    if (condition.is_true() || condition.is_false()) {
      from.push_back(original);
      to.push_back(payload(original, condition));
      ++rewrites;
      continue;
    }
    if (cost(condition) < 8)
      continue;
    for (const auto &slice: slices) {
      if (std::chrono::steady_clock::now() >= deadline || queries >= 512)
        break;
      const auto bits = slice.get_sort().bv_size();
      std::set<unsigned> values;
      z3::solver projected(*ctx_);
      projected.add(domain && condition);
      bool exhaustive = false;
      for (unsigned count = 0; count <= (1U << bits); ++count) {
        const auto verdict = check(projected);
        if (verdict == z3::unsat) {
          exhaustive = true;
          break;
        }
        if (verdict != z3::sat)
          break;
        const auto value =
                projected.get_model().eval(slice, true).get_numeral_uint();
        values.insert(value);
        projected.add(slice != ctx_->bv_val(value, bits));
      }
      if (!exhaustive)
        continue;
      auto candidate = membership(slice, values);
      // Also consider complementing a shorter interval set.
      std::set<unsigned> complement;
      for (unsigned i = 0; i < (1U << bits); ++i)
        if (!values.contains(i))
          complement.insert(i);
      const auto inverse = (!membership(slice, complement)).simplify();
      if (cost(inverse) < cost(candidate))
        candidate = inverse;
      if (cost(payload(original, candidate)) >= cost(current))
        continue;
      z3::solver proof(*ctx_);
      proof.add(domain && (condition != candidate));
      if (check(proof) != z3::unsat)
        continue;
      from.push_back(original);
      to.push_back(payload(original, candidate));
      ++rewrites;
      break;
    }
  }
  auto substituted = z3::expr(projection).substitute(from, to);
  // One memoized, local fold after the proved predicate substitutions.
  std::map<unsigned, std::pair<z3::expr, z3::expr>> memo;
  std::unordered_set<unsigned> inputIds, unknownNodes;
  for (const auto &input: inputs)
    inputIds.insert(input.id());
  const auto hasUnknown = [&](const z3::expr &root) {
    std::vector<z3::expr> pending{root};
    std::unordered_set<unsigned> seen;
    while (!pending.empty()) {
      const auto node = pending.back();
      pending.pop_back();
      if (!seen.insert(node.id()).second)
        continue;
      if (node.is_const() && node.decl().decl_kind() == Z3_OP_UNINTERPRETED &&
          !inputIds.contains(node.id()))
        return true;
      for (unsigned i = 0; i < node.num_args(); ++i)
        pending.push_back(node.arg(i));
    }
    return false;
  };
  std::vector<std::pair<z3::expr, bool>> work{{substituted, false}};
  unsigned joinedPayloadQueries = 0;
  while (!work.empty()) {
    const auto [node, ready] = work.back();
    work.pop_back();
    if (memo.contains(node.id()))
      continue;
    if (!ready && node.num_args()) {
      work.emplace_back(node, true);
      for (unsigned i = 0; i < node.num_args(); ++i)
        work.emplace_back(node.arg(i), false);
      continue;
    }
    z3::expr_vector args(*ctx_);
    for (unsigned i = 0; i < node.num_args(); ++i)
      args.push_back(memo.at(node.arg(i).id()).second);
    auto value = node.num_args() ? node.decl()(args) : node;
    value = fold::local(value);
    // Recover sign extension hidden in the machine's high:low dividend
    // assembly. The other operand supplies a width, not a guessed value.
    // Prove each proposed operand identity independently before the local
    // low-result div/rem identity is allowed to reduce its width.
    const auto kind = value.decl().decl_kind();
    if (wholeDomain && (kind == Z3_OP_BSDIV || kind == Z3_OP_BSDIV_I ||
                        kind == Z3_OP_BSREM || kind == Z3_OP_BSREM_I)) {
      for (unsigned side = 0; side < 2; ++side) {
        const auto other = value.arg(1 - side), operand = value.arg(side);
        if (!fold::kind(other, Z3_OP_SIGN_EXT) ||
            fold::kind(operand, Z3_OP_SIGN_EXT))
          continue;
        const auto bits = fold::width(other.arg(0));
        const auto candidate = z3::sext(
                operand.extract(bits - 1, 0).simplify(),
                fold::width(operand) - bits);
        z3::solver proof(*ctx_);
        proof.add(operand != candidate); // Unconditional, not just path-local.
        if (check(proof) == z3::unsat) {
          value = side ? value.decl()(value.arg(0), candidate)
                       : value.decl()(candidate, value.arg(1));
          ++rewrites;
        }
      }
    }
    // A machine branch can be redundant only under its own predicate (e.g.
    // a bit-test proves that an already-masked operand is one). Keep word
    // payloads intact and prove a branch substitution, not a guessed formula.
    if (wholeDomain && joinedPayloadQueries < 16 && value.is_bv() &&
        fold::width(value) >= 8 && fold::kind(value, Z3_OP_ITE) &&
        !value.arg(1).is_numeral() && !value.arg(2).is_numeral()) {
      const auto yes = value.arg(1), no = value.arg(2);
      const bool preferYes = cost(yes) < cost(no);
      for (unsigned attempt = 0; attempt < 2; ++attempt) {
        if (joinedPayloadQueries >= 16)
          break;
        const bool keepYes = attempt ? !preferYes : preferYes;
        z3::solver proof(*ctx_);
        proof.add(domain && (keepYes ? !value.arg(0) : value.arg(0)) &&
                  (yes != no));
        ++joinedPayloadQueries;
        if (check(proof) == z3::unsat) {
          value = keepYes ? yes : no;
          ++rewrites;
          break;
        }
      }
    }
    // Normalize only cones containing symbols absent from the export interface.
    // A masked-off machine flag must not force lowerExpression's whole-return
    // simplify fallback. Accept no invented value: an unknown symbol either
    // disappears by an identity, or remains unknown and lowering rejects it.
    bool unknown = node.is_const() &&
                   node.decl().decl_kind() == Z3_OP_UNINTERPRETED &&
                   !inputIds.contains(node.id());
    for (unsigned i = 0; i < node.num_args(); ++i)
      unknown |= unknownNodes.contains(node.arg(i).id());
    if (wholeDomain && unknown) {
      const auto normalized = value.simplify();
      if (!hasUnknown(normalized)) {
        value = normalized;
        unknown = false;
      }
    }
    if (unknown)
      unknownNodes.insert(node.id());
    memo.emplace(node.id(), std::make_pair(node, value));
  }
  auto result = memo.at(substituted.id()).second;
  if (wholeDomain)
    result = projection::bitPlanes(result, domain, check, rewrites);
  if (queryCount)
    *queryCount = queries;
  if (rewriteCount)
    *rewriteCount = rewrites;
  return result;
}
