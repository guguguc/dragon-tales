#pragma once

#include <dragon/lifters/ignil/MemoryEffects.hpp>
#include <dragon/lifters/ignil/IGNIL.hpp>
#include <dragon/lifters/ignil/StateAccess.hpp>

#include <z3++.h>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

/// Symbolic execution of IGNIL over Z3 bitvectors.
///
/// The executor interprets a Block (or any Op sequence) against a
/// SymbolicState, producing a Z3 expression for every value the block
/// computes. Registers and memory may be seeded concretely, symbolically, or
/// left undefined - an undefined location reads back as a fresh free
/// variable, so a block always executes even when its inputs are unknown.
///
/// Two uses drive the design:
///
///   1. Solving. Symbolise an input buffer, run a checksum/crypto block, then
///      ask the solver for an input that makes the output equal a target
///      value (SymbolicExecutor::solve).
///
///   2. Control-flow recovery. A JMP or CJMP whose target is a computed value
///      (a VM dispatch, a jump table, an opaque predicate) is resolved by
///      enumerating the target expression's satisfying values under the
///      accumulated path constraints. RunResult::successors then names the
///      concrete addresses actually reachable, which is what a CFG
///      reconstructor needs.
///
/// Everything here is architecture-agnostic: the executor only ever sees
/// ignil::Reg offsets, so an x86 block (dragon::x86 register descriptors) and
/// an AArch64 block (dragon::arm) run through the same code.
///
/// Only available when the library is built with -DDRAGON_USE_Z3=ON.
namespace dragon::ignil {

// ---------------------------------------------------------------------------
// Options
// ---------------------------------------------------------------------------

/// Tuning knobs for a SymbolicExecutor and the state it owns.
struct SymbolicOptions {
  /// Per-query Z3 timeout in milliseconds. A query that times out is reported
  /// as an unknown result (std::nullopt from the predicate helpers, a warning
  /// plus an unresolved branch from run()), never as a wrong answer.
  unsigned solverTimeoutMs = 5000;

  /// Upper bound on how many concrete addresses a symbolic LOAD/STORE address
  /// is allowed to resolve to. An address with more than this many satisfying
  /// values is left unresolved (a warning is recorded) rather than expanded
  /// into an unmanageable ite-chain.
  std::size_t maxAddressSolutions = 64;

  /// Upper bound on how many concrete targets a computed JMP/CJMP/CALL target
  /// is allowed to resolve to. This is the bound that matters for VM dispatch
  /// and jump-table recovery, so it is deliberately more generous than
  /// maxAddressSolutions.
  std::size_t maxBranchTargets = 256;

  /// Model the x86-64 / AArch64 rule that a 32-bit write to a 64-bit register
  /// clears the upper 32 bits (`mov eax, ...` zeroes RAX[63:32], and so does
  /// `mov w0, ...` for X0). Writes of 8 and 16 bits always preserve the
  /// surrounding bytes on every target, so they are unaffected. Turn this off
  /// for an architecture where a 32-bit write is a merge.
  bool zeroExtendOn32BitWrite = true;

  /// Reading a register or address that was never written yields a fresh free
  /// variable (the location is lazily symbolised, and the symbol is recorded
  /// so a model can report it). With this off, such a read yields zero
  /// instead - useful when a block should be run against a fully specified
  /// machine state and any gap is a bug in the setup.
  bool symbolizeUnmappedReads = true;

  /// Stop executing at the first terminator (JMP/CJMP/CALL/RET). Blocks
  /// produced by the block lifters end in exactly one terminator, so this is
  /// the right default. Turn it off to run a *trace* - a Block from
  /// liftTrace() splices many basic blocks together and its interior
  /// terminators must be stepped over, not stopped at. Successors are still
  /// recorded either way.
  bool stopAtTerminator = true;

  /// Read the analysis host's x86 RDTSC/RDTSCP by default. Each dynamic
  /// instruction gets one paired sample, recorded in RunResult. This is a
  /// concrete host environment assumption, not source-machine time replay.
  /// Explicit setConcreteOpaque overrides take precedence. Disable to keep
  /// timestamp results symbolic. Unsupported host instructions stay symbolic
  /// and produce a warning; no wall-clock or zero fallback is substituted.
  bool useHostTimestamps = true;

  /// Yield before an ambiguous LOAD, including two-literal pointer-valued
  /// reads. No assumed cursor register or bytecode classification is needed.
  bool forkMemoryReads = false;
};

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/// Outcome of executing a block.
enum class ExecStatus {
  Ok, ///< Every op executed.
  MalformedOp, ///< An op had the wrong operand count or a missing dst.
  UnsupportedOp, ///< An opcode this executor does not model.
  SolverFailure, ///< A query the run depended on returned unknown/timed out.
};

/// How a block left control flow.
enum class ExitKind {
  FallThrough, ///< Ran off the end without a terminator.
  Jump, ///< Unconditional JMP.
  ConditionalJump, ///< CJMP.
  Call, ///< CALL.
  Return, ///< RET.
  Error, ///< Execution stopped early; see ExecStatus.
};

/// One concrete address control flow can reach out of a block, together with
/// the condition under which it is reached.
///
/// A CJMP whose condition is provably constant under the path constraints
/// yields a single Successor - that is how an opaque predicate collapses.
/// A computed JMP whose target has N satisfying values yields N of them.
struct Successor {
  std::uint64_t address;
  z3::expr condition; ///< Bool-sorted guard for reaching `address`.
  bool taken = true; ///< For a CJMP: the true-side (taken) edge.
};

/// A soft problem that did not stop execution but that a caller relying on
/// completeness needs to know about - an address too symbolic to resolve, an
/// enumeration that hit its bound, a solver timeout on a branch feasibility
/// query. A RunResult with warnings is still usable; it just is not a
/// complete account of what the block can do.
struct ExecWarning {
  std::uint64_t address; ///< Machine address of the op that raised it.
  std::string message;
};

/// A LOAD or STORE whose address had too many satisfying values to expand.
///
/// The executor does not guess: such a LOAD yields a fresh symbol and such a
/// STORE is dropped, each with a warning. That is the right call for solving,
/// but a caller rebuilding code from the run - rather than asking the solver
/// about it - needs the access itself, and this is it: the address expression,
/// plus the value stored (STORE) or the symbol standing in for the value read
/// (LOAD).
struct UnresolvedAccess {
  bool isStore;
  std::uint64_t opAddress; ///< Machine address of the op.
  Width width; ///< Bits read or written.
  z3::expr address;
  z3::expr value;
};

/// One native analysis-host timestamp observation (never a source trace).
struct HostTimestamp {
  std::uint64_t address;
  OpaqueKind kind;
  std::uint64_t tsc;
  std::uint32_t aux; ///< IA32_TSC_AUX for RDTSCP; zero/unused for RDTSC.
};

/// An exact pause BEFORE a LOAD. chooseMemoryRead() adds the original guard,
/// specializes only the selected state, commits the read, and resumes at nextOp.
struct MemoryReadChoice {
  bool valueChoice = false;
  std::uint64_t opAddress = 0;
  std::uint64_t slot = 0; // source memory slot for a value choice
  std::size_t nextOp = 0;
  Value destination;
  z3::expr expression;
  std::vector<std::uint64_t> values;
  std::vector<z3::expr> guards;
};

/// What a run() did.
struct RunResult {
  private:
  friend class SymbolicExecutor;

  // Must precede Z3 expressions so it is destroyed after successor guards.
  std::shared_ptr<z3::context> ownedContext_;
  // A machine instruction expands into multiple OPAQUE result ops. Keep the
  // sample per run, not per static PC or in a restored SymbolicState.
  std::optional<HostTimestamp> pendingTimestamp_;
  unsigned timestampResultsSeen_ = 0;

  public:
  ExecStatus status = ExecStatus::Ok;
  ExitKind exit = ExitKind::FallThrough;
  std::string error; ///< Set when status != Ok.
  std::vector<Successor> successors;
  std::vector<ExecWarning> warnings;
  std::vector<UnresolvedAccess> unresolved;
  std::vector<HostTimestamp> hostTimestamps;
  std::optional<MemoryReadChoice> memoryChoice;

  struct Stats {
    std::size_t opsExecuted = 0;
    std::size_t solverQueries = 0;
    std::size_t addressesConcretized = 0;
  } stats;

  [[nodiscard]] bool ok() const { return status == ExecStatus::Ok; }

  /// True when every successor and memory access was resolved exactly - i.e.
  /// the successor list is the complete set of reachable addresses.
  [[nodiscard]] bool complete() const { return ok() && warnings.empty() && !memoryChoice; }
};

/// A satisfying assignment, mapping every free variable the executor created
/// to its concrete value.
///
/// Symbols are named by the caller at symbolisation time: a symbolic register
/// gets one symbol of the register's width, and a symbolic memory region of N
/// bytes gets N eight-bit symbols named `<region>[0]` .. `<region>[N-1]`, so
/// a recovered buffer can be read straight back out with bytes().
class Solution {
  public:
  /// Concrete value of one symbol, or nullopt if the model does not bind it
  /// (an unconstrained symbol Z3 chose not to name).
  [[nodiscard]] std::optional<std::uint64_t> value(std::string_view symbol) const;

  /// Bytes of a symbolic memory region, in address order. Returns {} if no
  /// region of that name was symbolised. Bytes the model left unconstrained
  /// come back as zero.
  [[nodiscard]] std::vector<std::uint8_t> bytes(std::string_view region) const;

  /// Every bound symbol.
  [[nodiscard]] const std::map<std::string, std::uint64_t> &values() const {
    return values_;
  }

  private:
  friend class SymbolicExecutor;
  std::map<std::string, std::uint64_t> values_;
  std::map<std::string, std::uint64_t> regionSizes_;
};

// ---------------------------------------------------------------------------
// SymbolicState
// ---------------------------------------------------------------------------

/// Register file, memory and path constraints, all as Z3 bitvectors.
///
/// Registers and memory are stored one byte at a time. That is what makes
/// sub-register aliasing come out right without any per-architecture table:
/// `Reg{0,32,"EAX"}` writes bytes 0..3, `Reg{1,8,"AH"}` writes byte 1, and a
/// later read of `Reg{0,64,"RAX"}` concatenates bytes 0..7 whatever mix of
/// widths produced them.
///
/// Copyable, so a caller can snapshot a state before a branch and explore
/// both sides (the copy shares the Z3 context, as Z3 expressions must).
class SymbolicState {
  public:
  explicit SymbolicState(z3::context &ctx, SymbolicOptions opts = {});

  [[nodiscard]] z3::context &ctx() const { return *ctx_; }
  [[nodiscard]] const SymbolicOptions &options() const { return opts_; }

  // -- registers ----------------------------------------------------------

  /// Write `value` to `r`, coercing it to the register's width. Honours
  /// SymbolicOptions::zeroExtendOn32BitWrite.
  void writeRegister(const Reg &r, const z3::expr &value);
  void writeRegister(const Reg &r, std::uint64_t value);

  /// Read `r` as a bitvector of the register's width. Bytes never written
  /// read as fresh symbols (or zero, per options).
  [[nodiscard]] z3::expr readRegister(const Reg &r) const;

  /// True if every byte of `r` has been written.
  [[nodiscard]] bool isRegisterDefined(const Reg &r) const;

  /// Bind `r` to a fresh free variable and return it. An empty name gets an
  /// auto-generated one.
  z3::expr symbolizeRegister(const Reg &r, std::string_view name = {});

  // -- temporaries --------------------------------------------------------

  void writeTemp(const Temp &t, const z3::expr &value);
  [[nodiscard]] std::optional<z3::expr> readTemp(const Temp &t) const;

  // -- memory -------------------------------------------------------------

  /// Store `value` little-endian at `addr`. The number of bytes written comes
  /// from the expression's own bitvector width, rounded up.
  void writeMemory(std::uint64_t addr, const z3::expr &value);

  /// Map a concrete blob - the usual way to supply a lookup table, a constant
  /// pool, or a captured stack frame.
  ///
  /// A blob of kImageThreshold bytes or more is kept as one immutable image
  /// shared between every copy of the state, not as one Z3 expression per
  /// byte, so mapping a whole executable costs a single allocation and a
  /// snapshot of the state stays cheap. Later writes land in a byte-granular
  /// overlay on top of it, exactly as they do for a small blob.
  void writeMemory(std::uint64_t addr, const std::vector<std::uint8_t> &bytes);

  /// Size from which a concrete blob is stored as a shared image.
  static constexpr std::size_t kImageThreshold = 256;

  /// Read `width` bits little-endian from `addr`. Unmapped bytes read as
  /// fresh symbols (or zero, per options).
  [[nodiscard]] z3::expr readMemory(std::uint64_t addr, Width width) const;

  /// True if every byte of [addr, addr + width/8) has been written.
  [[nodiscard]] bool isMemoryDefined(std::uint64_t addr, Width width) const;

  /// Fill [addr, addr + size) with fresh per-byte symbols named
  /// `<name>[0]`..`<name>[size-1]`, and remember the region so a Solution can
  /// hand the bytes back. Returns the region's bytes concatenated
  /// little-endian, which is the value a load of the whole region would see.
  z3::expr symbolizeMemory(std::uint64_t addr, std::uint64_t size,
                           std::string_view name);

  // Optional, watched physical-state footprint for resolved-loop analysis.
  // Snapshots share the observer; finish disables it in all of them.
  void beginAccessTrace(const std::vector<StateRange> &ranges) {
    accessTrace_ = std::make_shared<StateAccessTrace>(ranges);
  }
  std::vector<StateAccessTrace::Byte> endAccessTrace(bool *complete = nullptr) {
    if (complete)
      *complete = !accessTrace_ || accessTrace_->complete();
    if (!accessTrace_)
      return {};
    auto result = accessTrace_->finish();
    accessTrace_.reset();
    return result;
  }
  /// Analysis-time byte-range binding. Unlike an EAX write, a 32-bit binding
  /// does not clear neighboring bytes; instruction execution is unchanged.
  z3::expr symbolizeRange(bool memory, std::uint64_t key, Width width,
                          std::string_view name);

  // Independent, nested invocation collectors. Snapshots share conservative
  // all-read/all-write footprints, never branch-local LiveIn assumptions.
  std::shared_ptr<StateAccessTrace> beginCallTrace();
  void detachCallTrace(const std::shared_ptr<StateAccessTrace> &trace);
  void invalidateCallTraces();
  void observeCallAccess(bool memory, std::uint64_t key, std::uint64_t bytes,
                         bool write, bool control = false) const;
  z3::expr readControlMemory(std::uint64_t addr, Width width) const;

  // -- diffing ------------------------------------------------------------

  /// One contiguous run of bytes whose value differs between two states.
  struct Delta {
    enum class Kind : std::uint8_t { Register, Memory };

    Kind kind;
    /// Register-space byte offset, or memory address.
    std::uint64_t key;
    /// Width of the run, in bits.
    Width width;
    /// The value in *this* state, read back at `width`.
    z3::expr value;
  };

  /// Every register and memory byte whose stored value differs from `before`,
  /// coalesced into the widest runs that came from a single written value.
  ///
  /// This is the batch form of "read every location back and compare": a
  /// caller asking what a block changed makes one call instead of one
  /// readRegister / readMemory per candidate location. Bytes that neither
  /// state ever wrote are not reported - they are equal by construction, both
  /// reading back as the same lazily-named placeholder.
  ///
  /// `before` must share this state's Z3 context.
  [[nodiscard]] std::vector<Delta> diff(const SymbolicState &before) const;

  // -- merging ------------------------------------------------------------

  /// Exact physical-state join at a completed native-block boundary. Select
  /// incoming when condition is true, this state otherwise. Unlike merge(),
  /// this retains guarded byte values and guarded constraint suffixes; it does
  /// not introduce unconstrained tops. Concrete image backing must be shared.
  /// Block-local temporaries are discarded. Effect-recording states and active
  /// access observers are deliberately excluded. Returns a counterexample
  /// formula for the physical-value/constraint projection (must be UNSAT).
  z3::expr joinGuarded(const SymbolicState &incoming,
                       const z3::expr &condition);


  /// Join `incoming` into this state: every register or memory byte the two
  /// disagree on is replaced, here, by a fresh free variable ("the value is
  /// not the same on every path into this point"). Bytes they agree on are
  /// left alone. Returns the locations that were symbolised, coalesced into
  /// runs the way diff() does, each with its new variable as `value`; an empty
  /// result means `incoming` added nothing, which is the fixed-point test of
  /// a worklist exploration.
  ///
  /// This is the join of a control-flow recovery that visits each program
  /// point once instead of once per path: run a block, merge the state it
  /// produced into the one stored for its successor, and revisit the
  /// successor only if the merge changed something. A loop counter that is a
  /// constant on the way in and a different constant around the back edge
  /// becomes a variable, and the loop's exit branch - provably not taken
  /// while the counter was still that constant - becomes reachable.
  ///
  /// `tag` names the merge point and goes into the variables' names
  /// (`top@<tag>!m<addr>` / `top@<tag>!r<offset>`). A byte that already holds
  /// a variable made by an earlier merge under the same tag is already "any
  /// value", so it is not symbolised again; that is what makes repeated merges
  /// into one state converge. Path constraints are not merged - this state
  /// keeps its own.
  ///
  /// `incoming` must share this state's Z3 context.
  std::vector<Delta> merge(const SymbolicState &incoming, std::string_view tag);

  /// Opt in before executing a path. All IGNIL loads/stores use a shared,
  /// initially unconstrained array, NOT captured concrete memory. State copies
  /// include the event log. Widening/merging effect histories is unsupported.
  bool enableMemoryEffects() {
    if (memoryEffects_) return false;
    memoryEffects_.emplace(*ctx_);
    return true;
  }
  [[nodiscard]] MemoryEffects *memoryEffects() {
    return memoryEffects_ ? &*memoryEffects_ : nullptr;
  }
  [[nodiscard]] const MemoryEffects *memoryEffects() const {
    return memoryEffects_ ? &*memoryEffects_ : nullptr;
  }

  // -- path constraints ---------------------------------------------------

  void addConstraint(const z3::expr &c);

  /// Rewrite concrete execution state under an equality already retained as
  /// a path constraint. Entry symbols and constraints themselves stay intact.
  void specialize(const z3::expr &expression, const z3::expr &value);
  /// Apply several independently justified equalities in one state traversal.
  void specialize(const z3::expr_vector &from, const z3::expr_vector &to);
  [[nodiscard]] bool hasMemoryPrefix(std::uint32_t upper) const;
  [[nodiscard]] const std::vector<z3::expr> &constraints() const {
    return constraints_;
  }

  // -- free variables -----------------------------------------------------

  /// Every free variable created so far, by name. Used to read a model back.
  [[nodiscard]] const std::map<std::string, z3::expr> &symbols() const {
    return symbols_;
  }

  /// Byte size of each symbolised memory region, by name.
  [[nodiscard]] const std::map<std::string, std::uint64_t> &regions() const {
    return regions_;
  }

  /// Create (or return the existing) free variable of the given name.
  z3::expr symbol(std::string_view name, Width width) const;

  private:
  friend class StateSummary;
  z3::expr readRange(const StateRange &range) const;
  void writeRange(const StateRange &range, const z3::expr &value);
  /// One stored byte, remembered as a slice of the value it was written from
  /// rather than as a detached 8-bit expression: this byte is
  /// `extract(index*8+7, index*8, source)`.
  ///
  /// Keeping the provenance is what lets readBytes hand back the original
  /// expression when a location is read at exactly the width it was written.
  /// Without it, writing a 64-bit value and reading it straight back produces
  /// a concat of eight extracts that Z3 does not always fold away - correct,
  /// but unreadable and needlessly large for the solver.
  struct StoredByte {
    z3::expr source;
    unsigned index;
  };

  using ByteStore = std::map<std::uint64_t, StoredByte>;

  /// An immutable concrete blob, shared by every copy of the state.
  struct Image {
    std::uint64_t base;
    std::shared_ptr<const std::vector<std::uint8_t>> bytes;
  };

  /// The image byte at `addr`, if any image covers it. Later images shadow
  /// earlier ones.
  [[nodiscard]] std::optional<std::uint8_t> imageByte(std::uint64_t addr) const;

  /// The concrete value of one byte, when it has one: a byte of an image, or a
  /// stored byte whose source is a literal. `images` says whether the store
  /// is backed by images_ (memory) or not (registers).
  [[nodiscard]] std::optional<std::uint8_t>
  concreteByte(const ByteStore &store, std::uint64_t key, bool images) const;

  /// One byte out of a byte store, or the free variable standing in for it if
  /// the location was never written. `kind` is "reg" or "mem" and only picks
  /// the placeholder's name.
  [[nodiscard]] z3::expr readByte(const ByteStore &store, std::uint64_t key,
                                  std::string_view kind) const;

  /// Split `value` into little-endian bytes at `base`.
  void writeBytes(ByteStore &store, std::uint64_t base, const z3::expr &value,
                  Width width);

  /// Reassemble `width` bits little-endian from `base`.
  [[nodiscard]] z3::expr readBytes(const ByteStore &store, std::uint64_t base,
                                   Width width, std::string_view kind) const;

  z3::context *ctx_;
  SymbolicOptions opts_;

  // Byte-granular stores. Keys are register-space byte offsets and memory
  // addresses respectively.
  std::shared_ptr<StateAccessTrace> accessTrace_;
  struct CallTrace {
    std::shared_ptr<StateAccessTrace> unionTrace;
    // Definite writes on this path; snapshots copy rather than share them.
    std::set<std::pair<bool, std::uint64_t>> written;
  };
  mutable std::vector<CallTrace> callTraces_;
  ByteStore regBytes_;
  ByteStore memBytes_;

  // Concrete images under memBytes_. A read consults the overlay first, so a
  // write over an image needs no copy of it.
  std::vector<Image> images_;

  std::map<std::uint32_t, z3::expr> temps_;
  std::vector<z3::expr> constraints_;
  std::optional<MemoryEffects> memoryEffects_;

  mutable std::map<std::string, z3::expr> symbols_;
  std::map<std::string, std::uint64_t> regions_;
};

// ---------------------------------------------------------------------------
// SymbolicExecutor
// ---------------------------------------------------------------------------

/// Executes IGNIL ops against a SymbolicState and answers solver queries
/// about the result.
///
/// State persists across run() calls, so walking a path is just a sequence of
/// runs:
///
///     SymbolicExecutor exec;
///     exec.symbolizeMemory(0x4000, 16, "input");
///     exec.setRegister(x86::RDI, 0x4000);
///     RunResult r = exec.run(block);
///     auto sol = exec.solve(exec.readRegister(x86::RAX) == exec.bv(0xdeadbeef, 64));
///
class SymbolicExecutor {
  public:
  /// Construct with a privately owned Z3 context.
  explicit SymbolicExecutor(SymbolicOptions opts = {});

  /// Construct against a caller-owned context, so expressions can be shared
  /// with other Z3 work (SliceExprZ3, an external solver). The context must
  /// outlive the executor.
  explicit SymbolicExecutor(z3::context &ctx, SymbolicOptions opts = {});

  SymbolicExecutor(const SymbolicExecutor &) = delete;
  SymbolicExecutor &operator=(const SymbolicExecutor &) = delete;

  [[nodiscard]] z3::context &ctx() const { return *ctx_; }
  [[nodiscard]] const SymbolicOptions &options() const { return opts_; }
  [[nodiscard]] SymbolicState &state() { return state_; }
  [[nodiscard]] const SymbolicState &state() const { return state_; }

  /// Drop all register, memory, temporary and constraint state. Keeps the
  /// context and the options.
  void reset();

  /// Replace the state wholesale - e.g. restore a snapshot taken before a
  /// branch. The state must belong to this executor's context.
  void setState(SymbolicState state);

  /// Locations whose value changed since the snapshot `before` was taken.
  /// Convenience forwarder for SymbolicState::diff.
  [[nodiscard]] std::vector<SymbolicState::Delta>
  diff(const SymbolicState &before) const {
    return state_.diff(before);
  }

  // -- convenience builders ----------------------------------------------

  /// A concrete bitvector in this executor's context.
  [[nodiscard]] z3::expr bv(std::uint64_t value, Width width) const;

  // -- machine setup ------------------------------------------------------

  void setRegister(const Reg &r, std::uint64_t value);
  void setRegister(const Reg &r, const z3::expr &value);
  z3::expr symbolizeRegister(const Reg &r, std::string_view name = {});

  /// Give an already computed register value a fresh exact name. Retain the
  /// defining equality and rewrite nonconstant word/slice copies throughout
  /// physical state. This does not skip execution or summarize memory effects.
  /// The name must be absent from the current state; effect mode is excluded.
  z3::expr bindRegisterValue(const Reg &r, std::string_view name);

  void mapMemory(std::uint64_t addr, const std::vector<std::uint8_t> &bytes);
  void setMemory(std::uint64_t addr, const z3::expr &value);
  z3::expr symbolizeMemory(std::uint64_t addr, std::uint64_t size,
                           std::string_view name);

  /// Add a constraint that holds for the rest of the run - a precondition on
  /// an input ("every input byte is printable ASCII"), or a fact recovered
  /// from a trace.
  void assume(const z3::expr &c);

  /// Rewrite physical state using lhs == rhs only after proving that equality
  /// from the retained constraints. Unknown returns nullopt; false leaves the
  /// state unchanged. Memory-effects recording is deliberately excluded.
  std::optional<bool> specializeEquality(const z3::expr &equality);


  /// Make an OPAQUE op return concrete results instead of a symbol / an
  /// uninterpreted function, so a concolic trace stays fully concrete through
  /// an anti-tamper CPUID (whose symbolic result otherwise flows into a VM's
  /// dispatch key and strands execution on the solver). An op is concretised
  /// only when its kind and its operands match a registration; everything else
  /// keeps the configured default (host timestamps, symbolic other kinds).
  /// Explicit overrides take precedence over native timestamp sampling.
  ///
  /// `selector` identifies which invocation to concretise from its operands.
  /// For CPUID (operands leaf, subleaf) it is packed leaf/subleaf, which
  /// packConcreteOpaqueSelector() builds; for RDTSC / RDTSCP (no operands) it
  /// is 0. `results` are the per-result-index values in the kind's own order
  /// (CPUID: EAX, EBX, ECX, EDX; RDTSC: EAX-low, EDX-high); indices past the
  /// end keep the default behaviour.
  void setConcreteOpaque(OpaqueKind kind, std::uint64_t selector,
                         std::vector<std::uint64_t> results);

  /// Pack a CPUID leaf and subleaf into a setConcreteOpaque() selector.
  [[nodiscard]] static constexpr std::uint64_t
  packConcreteOpaqueSelector(std::uint64_t leaf, std::uint64_t subleaf) {
    return (leaf << 32) | (subleaf & 0xffffffffULL);
  }

  /// Suffix for unresolved-load and UNDEF symbols (UNDEF also distinguishes
  /// destination/width). They are named
  /// after the op's address and its position in the run, so running the same
  /// block twice hands out the same names - and the two loads, which may well
  /// read different memory, become one variable. A caller that runs one block
  /// in several contexts sets a tag per context to keep them apart. Empty (the
  /// default) leaves the names as they were.
  /// Change only the timestamp source; register/memory state is unchanged.
  void setHostTimestamps(bool enabled) { opts_.useHostTimestamps = enabled; }
  void setForkMemoryReads(bool enabled) { opts_.forkMemoryReads = enabled; }
  /// Commit a paused read under its original guard. The caller must restore
  /// the exact yielded state first when selecting an alternative branch.
  bool chooseMemoryRead(const MemoryReadChoice &choice, std::size_t index);

  void setFreshTag(std::string tag) { freshTag_ = std::move(tag); }
  [[nodiscard]] const std::string &freshTag() const { return freshTag_; }

  /// Simplify pure projection guards only after proving replacements under
  /// an explicit domain. No machine-state writes or hidden path assumptions.
  /// Uses bounded finite-bit guard projection; unsupported/expensive cases
  /// retain the original expression. Data DAGs are folded locally, not globally
  /// bit-split. Query/accepted-rewrite counts are optional output statistics.
  z3::expr simplifyProjection(const z3::expr &expression,
                              const z3::expr &domain,
                              const std::vector<z3::expr> &inputs,
                              unsigned timeoutMs = 2000,
                              std::size_t *queries = nullptr,
                              std::size_t *rewrites = nullptr) const;

  // -- execution ----------------------------------------------------------

  /// Execute every op of `block` against the current state.
  RunResult run(const Block &block);
  RunResult runFrom(const Block &block, std::size_t firstOp);

  /// Execute an arbitrary op sequence - a slice of a block, or ops built by
  /// hand.
  RunResult run(const std::vector<Op> &ops);
  RunResult runFrom(const std::vector<Op> &ops, std::size_t firstOp);

  /// Execute one op, appending any successors and warnings it produces to
  /// `result`. Returns Ok unless the op was malformed or unsupported.
  ExecStatus step(const Op &op, RunResult &result);

  // -- reading the machine ------------------------------------------------

  [[nodiscard]] z3::expr readRegister(const Reg &r) const;
  [[nodiscard]] z3::expr readMemory(std::uint64_t addr, Width width) const;
  [[nodiscard]] std::optional<z3::expr> readTemp(const Temp &t) const;

  // -- solver queries -----------------------------------------------------

  /// Is `condition` satisfiable together with the path constraints?
  /// nullopt means the solver gave up (timeout / unknown).
  [[nodiscard]] std::optional<bool> isSatisfiable(const z3::expr &condition);

  /// Does `condition` hold on every model of the path constraints?
  [[nodiscard]] std::optional<bool> proves(const z3::expr &condition);

  /// Concrete value of `e` if the path constraints force exactly one, else
  /// nullopt. This is the "did the obfuscation actually compute a constant?"
  /// query, and the same uniqueness test slice::ValueEnumerator uses.
  [[nodiscard]] std::optional<std::uint64_t> evaluate(const z3::expr &e);

  /// Up to `max` distinct satisfying values of `e`, in the order the solver
  /// produced them. `exhaustive`, when given, is set to true only if the
  /// enumeration ran out of values rather than hitting `max` - i.e. the
  /// returned list is the complete set.
  [[nodiscard]] std::vector<std::uint64_t>
  enumerate(const z3::expr &e, std::size_t max, bool *exhaustive = nullptr);

  /// Solve the path constraints, optionally with an extra goal, and report a
  /// satisfying assignment for every symbol the executor created.
  [[nodiscard]] std::optional<Solution> solve();
  [[nodiscard]] std::optional<Solution> solve(const z3::expr &goal);
  [[nodiscard]] std::optional<Solution>
  solve(const std::vector<z3::expr> &goals);

  private:
  // Value/expression plumbing.
  [[nodiscard]] z3::expr eval(const Value &v) const;
  [[nodiscard]] z3::expr coerce(const z3::expr &e, Width width) const;
  void writeDst(const Value &dst, const z3::expr &value);

  /// The value an OPAQUE op produces: a genuine Z3 uninterpreted function of
  /// the operands for a pure kind (two CPUIDs with the same leaf are provably
  /// equal), a paired native host timestamp by default, or a symbolic result
  /// when timestamp sampling is disabled/unavailable.
  z3::expr opaqueValue(const Op &op, Width dstWidth, RunResult &result);

  [[nodiscard]] z3::expr binary(Opcode op, const z3::expr &lhs,
                                const z3::expr &rhs, Width dstWidth) const;
  [[nodiscard]] z3::expr unary(Opcode op, const z3::expr &src,
                               Width dstWidth) const;
  [[nodiscard]] z3::expr shift(Opcode op, const z3::expr &lhs,
                               const z3::expr &rhs) const;
  [[nodiscard]] z3::expr floatBinary(Opcode op, const z3::expr &lhs,
                                     const z3::expr &rhs) const;

  /// Turn a possibly-symbolic address into concrete candidates. Returns
  /// nullopt when the address has more satisfying values than the bound
  /// allows (or the solver gave up), in which case a warning is recorded.
  [[nodiscard]] std::optional<std::vector<std::uint64_t>>
  concretize(const z3::expr &addr, std::size_t max, const Op &op,
             std::string_view what, RunResult &result);

  /// Resolve a branch target expression to successors under `guard`.
  void addSuccessors(const z3::expr &target, const z3::expr &guard, bool taken,
                     const Op &op, RunResult &result);

  ExecStatus stepMemory(const Op &op, RunResult &result);
  ExecStatus stepBranch(const Op &op, RunResult &result);

  /// Solver primed with the current path constraints.
  z3::solver &solver();

  static void warn(RunResult &result, const Op &op, std::string message);

  std::shared_ptr<z3::context> ownedCtx_;
  z3::context *ctx_;
  SymbolicOptions opts_;
  SymbolicState state_;

  // Path constraints are only ever appended during a run, so the solver can
  // be kept primed and topped up rather than rebuilt per query. It is rebuilt
  // if the constraint list ever shrinks (reset(), setState()).
  z3::solver solver_;
  std::size_t assertedConstraints_ = 0;

  // A SAT query with extra assumptions also witnesses satisfiability of the
  // base constraints. Reuse that fact for literal-true branches until another
  // constraint is appended. reset()/setState() invalidate it even when a
  // restored state has the same number of constraints.
  std::optional<std::size_t> satisfiableConstraints_;

  std::string freshTag_;

  // Concrete overrides for OPAQUE ops, keyed by (kind, operand selector).
  // Empty in the common case, so opaqueValue() pays nothing for it.
  std::map<std::pair<OpaqueKind, std::uint64_t>, std::vector<std::uint64_t>>
      concreteOpaque_;
};

} // namespace dragon::ignil
