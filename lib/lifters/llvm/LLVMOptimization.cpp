#include <dragon/lifters/llvm/LLVMLifter.hpp>

#include "passes/Passes.hpp"

#include <llvm/IR/Verifier.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Support/Error.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/Utils/Cloning.h>

namespace {
bool validModule(const llvm::Module &module, std::string *error) {
  std::string diagnostics;
  llvm::raw_string_ostream stream(diagnostics);
  const bool valid = !llvm::verifyModule(module, &stream);
  if (error)
    *error = std::move(diagnostics);
  return valid;
}
} // namespace

bool dragon::llvmlifter::LLVMLifter::verify(std::string *error) const {
  return validModule(*module_, error);
}

bool dragon::llvmlifter::LLVMLifter::runPassPipeline(std::string_view pipeline,
                                                     std::string *error) {
  if (error)
    error->clear();
  if (pipeline.empty() || pipeline.find('\0') != std::string_view::npos) {
    if (error)
      *error = "LLVM pass pipeline must be nonempty and contain no NUL";
    return false;
  }
  if (!verify(error))
    return false;

  // Parse first, then run on a clone. Bad syntax or invalid transformed IR
  // leaves the caller's module untouched. This is an LLVM structural check,
  // not a semantic-equivalence proof or a sandbox for arbitrary pass names.
  // Explicit scalar export pipeline: retain O2 arithmetic/CFG optimization,
  // without re-vectorizing small reconstructed predicate masks for execution.
  const bool scalar = pipeline == "dragon-scalar-o2";
  llvm::PipelineTuningOptions tuning;
  if (scalar) {
    tuning.LoopVectorization = false;
    tuning.SLPVectorization = false;
  }
  llvm::PassBuilder builder(nullptr, tuning);
  registerLoopReductionPass(builder);
  registerModularPolynomialPass(builder);
  registerLoopCleanupPass(builder);
  registerWordCleanupPass(builder);
  registerScalarLoopProposalPass(builder);
  llvm::ModulePassManager passes;
  if (scalar) {
    // The textual default<O2> parser applies its own tuning defaults. Build
    // directly so the scalar tuning above actually reaches the pipeline.
    passes = builder.buildPerModuleDefaultPipeline(llvm::OptimizationLevel::O2);
  } else if (auto failure = builder.parsePassPipeline(passes, pipeline)) {
    const auto message = llvm::toString(std::move(failure));
    if (error)
      *error = message;
    return false;
  }
  auto candidate = llvm::CloneModule(*module_);
  llvm::LoopAnalysisManager loops;
  llvm::FunctionAnalysisManager functions;
  llvm::CGSCCAnalysisManager cgscc;
  llvm::ModuleAnalysisManager modules;
  builder.registerModuleAnalyses(modules);
  builder.registerCGSCCAnalyses(cgscc);
  builder.registerFunctionAnalyses(functions);
  builder.registerLoopAnalyses(loops);
  builder.crossRegisterProxies(loops, functions, cgscc, modules);
  passes.run(*candidate, modules);
  if (!validModule(*candidate, error))
    return false;
  module_ = std::move(candidate);
  return true;
}
