#pragma once

namespace llvm {
class PassBuilder;
}

namespace dragon::llvmlifter {
// Registered as function(dragon-coalesce-add-reductions) in PassBuilder.
void registerLoopReductionPass(llvm::PassBuilder &builder);
// Registered as function(dragon-normalize-modular-polynomials) and
// function(dragon-fold-small-selects).
void registerModularPolynomialPass(llvm::PassBuilder &builder);
// Structural loop cleanup and presentation-only final naming.
void registerLoopCleanupPass(llvm::PassBuilder &builder);
// Integer word reconstruction and redundant zero-count rotation guards.
void registerWordCleanupPass(llvm::PassBuilder &builder);
// Adds scalar-loop hypotheses; never replaces the original function.
void registerScalarLoopProposalPass(llvm::PassBuilder &builder);
} // namespace dragon::llvmlifter
