#include <dragon/lifters/ignil/MemoryEffects.hpp>
#include <stdexcept>

namespace dragon::ignil {
namespace {
void validate(const z3::expr &address, unsigned width) {
  if (!address.is_bv() || address.get_sort().bv_size() != 64 || !width ||
      width % 8 || width > 4096)
    throw std::invalid_argument("memory effects require BV64 addresses and "
                                "byte-sized values <= 4096 bits");
}
z3::expr fresh(z3::context &ctx, const char *prefix, const z3::sort &sort) {
  return z3::expr(ctx, Z3_mk_fresh_const(ctx, prefix, sort));
}
} // namespace
MemoryEffects::MemoryEffects(z3::context &ctx) :
    initial_(fresh(ctx, "memory.initial",
                   ctx.array_sort(ctx.bv_sort(64), ctx.bv_sort(8)))),
    memory_(initial_) {}

z3::expr MemoryEffects::read(const z3::expr &address, unsigned width) const {
  validate(address, width);
  if (&address.ctx() != &memory_.ctx())
    throw std::invalid_argument("mixed memory contexts");
  auto &ctx = memory_.ctx();
  z3::expr result = z3::select(memory_, address);
  for (unsigned i = 1; i < width / 8; ++i)
    result = z3::concat(z3::select(memory_, address + ctx.bv_val(i, 64)),
                        result);
  return result;
}

z3::expr MemoryEffects::load(const z3::expr &address, unsigned width,
                             std::uint64_t pc) {
  auto actual = read(address, width);
  auto token =
          fresh(memory_.ctx(), "memory.load", memory_.ctx().bv_sort(width));
  constraints_.push_back(token == actual);
  events_.push_back({false, pc, width, address, token});
  return token;
}

void MemoryEffects::store(const z3::expr &address, const z3::expr &value,
                          std::uint64_t pc) {
  if (!value.is_bv() || &address.ctx() != &memory_.ctx() ||
      &value.ctx() != &memory_.ctx())
    throw std::invalid_argument("invalid memory store context/value");
  const auto width = value.get_sort().bv_size();
  validate(address, width);
  auto updated = memory_;
  for (unsigned i = 0; i < width / 8; ++i)
    updated = z3::store(updated, address + memory_.ctx().bv_val(i, 64),
                        value.extract(i * 8 + 7, i * 8));
  events_.push_back({true, pc, width, address, value});
  memory_ = updated;
}
} // namespace dragon::ignil
