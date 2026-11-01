#pragma once

  #include <stddef.h>
  #include <stdint.h>

  #ifdef __cplusplus
  extern "C" {
  #endif

  // -- Enums ---

  typedef enum {
      DRAGON_ARCH_UNKNOWN = 0,
      DRAGON_ARCH_X86_32,
      DRAGON_ARCH_X86_64,
      DRAGON_ARCH_ARM32,
      DRAGON_ARCH_ARM64,
      DRAGON_ARCH_RISCV32,
      DRAGON_ARCH_RISCV64,
  } dragon_architecture_t;

  typedef enum {
      DRAGON_STRATEGY_LINEAR_SWEEP = 0,
      DRAGON_STRATEGY_RECURSIVE_TRAVERSAL,
  } dragon_strategy_t;

  typedef enum {
      DRAGON_SYNTAX_INTEL = 0,
      DRAGON_SYNTAX_ATT   = 1,
  } dragon_syntax_t;

  // -- Opaque handles ------------------------------------------------------------

  typedef struct dragon_config      dragon_config_t;
  typedef struct dragon_graph       dragon_graph_t;
  typedef struct dragon_disasm      dragon_disasm_t;
  typedef struct dragon_block       dragon_block_t;
  typedef struct dragon_function    dragon_function_t;

  // dragon_instruction_t is a pointer INTO the graph listing - no destroy needed,
  // valid as long as the owning graph is alive.
  typedef struct dragon_instruction dragon_instruction_t;

  // -- Configuration -------------------------------------------------------------

  dragon_config_t*  dragon_config_create(dragon_syntax_t syntax, dragon_strategy_t strategy);
  void              dragon_config_destroy(dragon_config_t* c);
  dragon_syntax_t   dragon_config_syntax(const dragon_config_t* c);
  dragon_strategy_t dragon_config_strategy(const dragon_config_t* c);

  // LLVM CPU name forwarded to MCSubtargetInfo (e.g. "cortex-a8", "skylake").
  // An empty / NULL value keeps the "generic" baseline for the target triple.
  // ARM32 examples: "arm926ej-s" enables BX/BLX; "cortex-a8" enables Thumb2.
  void        dragon_config_set_cpu(dragon_config_t* c, const char* cpu);
  const char* dragon_config_cpu(const dragon_config_t* c);

  // LLVM feature string forwarded to MCSubtargetInfo (e.g. "+v4t", "+avx2").
  // Comma-separated list; '+' enables a feature, '-' disables it.
  // ARM32 example: "+v4t" adds the BX instruction; "+v7,+neon" targets ARMv7.
  void        dragon_config_set_features(dragon_config_t* c, const char* features);
  const char* dragon_config_features(const dragon_config_t* c);

  // Enable (1) or disable (0) diagnostic logging to stderr.
  void dragon_config_set_logging(dragon_config_t* c, int enabled);
  int  dragon_config_logging(const dragon_config_t* c);

  // -- Graph ---

  dragon_graph_t* dragon_graph_create(dragon_architecture_t arch);
  void            dragon_graph_destroy(dragon_graph_t* g);

  size_t dragon_graph_size(const dragon_graph_t* g);
  int    dragon_graph_empty(const dragon_graph_t* g);

  // Returns pointer into the graph - valid while graph is alive. No destroy.
  const dragon_instruction_t* dragon_graph_get_instruction(
      const dragon_graph_t* g, uint64_t address);

  // Returns heap-allocated views - caller must destroy.
  dragon_block_t*    dragon_graph_get_block(const dragon_graph_t* g, uint64_t address);
  dragon_function_t* dragon_graph_get_function(const dragon_graph_t* g, uint64_t address);

  // Iterate valid addresses via callbacks (avoids exposing sets to C).
  void dragon_graph_each_instruction(const dragon_graph_t* g,
      void (*cb)(const dragon_instruction_t*, void* user), void* user);
  void dragon_graph_each_block_address(const dragon_graph_t* g,
      void (*cb)(uint64_t addr, void* user), void* user);
  void dragon_graph_each_function_address(const dragon_graph_t* g,
      void (*cb)(uint64_t addr, void* user), void* user);

  // -- Disassembler --------------------------------------------------------------

  dragon_disasm_t* dragon_disasm_create(dragon_architecture_t arch,
                                        const dragon_config_t* config);
  void             dragon_disasm_destroy(dragon_disasm_t* d);
  int              dragon_disasm_valid(const dragon_disasm_t* d);

  // Disassemble raw bytes and return a graph. Caller destroys the graph.
  dragon_graph_t*  dragon_disasm_disassemble(dragon_disasm_t* d,
                                             const uint8_t* bytes,
                                             size_t len,
                                             uint64_t base_address);

  // Disassemble and run architecture-specific analysis (block and function
  // discovery). Returns a fully populated graph. Caller destroys the graph.
  dragon_graph_t*  dragon_disasm_analyze(dragon_disasm_t* d,
                                         const uint8_t* bytes,
                                         size_t len,
                                         uint64_t base_address);

  // -- Loader --------------------------------------------------------------------

  typedef enum {
      DRAGON_FORMAT_UNKNOWN = 0,
      DRAGON_FORMAT_ELF,
      DRAGON_FORMAT_PE,
  } dragon_format_t;

  typedef enum {
      DRAGON_SYMBOL_UNKNOWN = 0,
      DRAGON_SYMBOL_FUNCTION,
      DRAGON_SYMBOL_OBJECT,
      DRAGON_SYMBOL_SECTION,
      DRAGON_SYMBOL_FILE,
  } dragon_symbol_kind_t;

  typedef struct dragon_loader dragon_loader_t;

  // Load an ELF or PE/COFF image from a file or from bytes already in memory.
  // Returns NULL on failure; when `err` is non-NULL a NUL-terminated reason of
  // at most `err_cap` bytes is written. Caller destroys the loader.
  dragon_loader_t* dragon_load_file(const char* path, char* err, size_t err_cap);
  dragon_loader_t* dragon_load_bytes(const uint8_t* bytes, size_t len,
                                     char* err, size_t err_cap);
  void             dragon_loader_destroy(dragon_loader_t* l);

  dragon_format_t       dragon_loader_format(const dragon_loader_t* l);
  dragon_architecture_t dragon_loader_architecture(const dragon_loader_t* l);
  int      dragon_loader_is_64bit(const dragon_loader_t* l);
  // 1 if the image has an entry point; dragon_loader_entry is valid only then.
  int      dragon_loader_has_entry(const dragon_loader_t* l);
  uint64_t dragon_loader_entry(const dragon_loader_t* l);
  uint64_t dragon_loader_image_base(const dragon_loader_t* l);

  // Sections. The returned name is borrowed - valid while the loader is alive.
  // Permissions (0/1) and placement are written to the out-parameters, each of
  // which may be NULL. Returns NULL for an out-of-range index.
  size_t      dragon_loader_section_count(const dragon_loader_t* l);
  const char* dragon_loader_section(const dragon_loader_t* l, size_t index,
                                    uint64_t* out_addr, uint64_t* out_vsize,
                                    int* out_r, int* out_w, int* out_x);
  // Borrowed file bytes of a section; out_len receives the length.
  const uint8_t* dragon_loader_section_bytes(const dragon_loader_t* l,
                                             size_t index, size_t* out_len);

  // ELF PT_LOAD segments ("LOAD0", "LOAD1", ...): what the system loader maps,
  // and the only layout left when a protector strips the section headers.
  // Same conventions as the section accessors above; none for PE.
  size_t      dragon_loader_segment_count(const dragon_loader_t* l);
  const char* dragon_loader_segment(const dragon_loader_t* l, size_t index,
                                    uint64_t* out_addr, uint64_t* out_vsize,
                                    int* out_r, int* out_w, int* out_x);
  const uint8_t* dragon_loader_segment_bytes(const dragon_loader_t* l,
                                             size_t index, size_t* out_len);

  // Symbols. Name borrowed, valid while the loader is alive. Out-parameters may
  // be NULL. Returns NULL for an out-of-range index.
  size_t      dragon_loader_symbol_count(const dragon_loader_t* l);
  const char* dragon_loader_symbol(const dragon_loader_t* l, size_t index,
                                   uint64_t* out_addr, uint64_t* out_size,
                                   dragon_symbol_kind_t* out_kind,
                                   int* out_imported, int* out_exported);

  // Read up to `cap` bytes from the image's virtual address space into `out`.
  // Returns the number of bytes written, or 0 if [addr, addr+cap) is unmapped.
  size_t dragon_loader_read_virtual(const dragon_loader_t* l, uint64_t addr,
                                    uint8_t* out, size_t cap);

  // Disassemble every executable section into a populated graph built for the
  // image's detected architecture. `config` may be NULL for defaults. Caller
  // destroys the graph.
  dragon_graph_t* dragon_loader_disassemble(const dragon_loader_t* l,
                                            const dragon_config_t* config);

  // -- Instruction ---------------------------------------------------------------

  uint64_t    dragon_instruction_address(const dragon_instruction_t* i);
  uint8_t     dragon_instruction_size(const dragon_instruction_t* i);
  const char* dragon_instruction_mnemonic(const dragon_instruction_t* i);
  const char* dragon_instruction_operands(const dragon_instruction_t* i);
  const char* dragon_instruction_disassembly(const dragon_instruction_t* i);
  const char* dragon_instruction_pattern(const dragon_instruction_t* i);

  const uint8_t* dragon_instruction_bytes(
      const dragon_instruction_t* i, size_t* out_len);
  const uint8_t* dragon_instruction_chromosome_mask(
      const dragon_instruction_t* i, size_t* out_len);

  int    dragon_instruction_is_block_start(const dragon_instruction_t* i);
  int    dragon_instruction_is_function_start(const dragon_instruction_t* i);
  int    dragon_instruction_is_prologue(const dragon_instruction_t* i);
  int    dragon_instruction_is_return(const dragon_instruction_t* i);
  int    dragon_instruction_is_call(const dragon_instruction_t* i);
  int    dragon_instruction_is_jump(const dragon_instruction_t* i);
  int    dragon_instruction_is_conditional(const dragon_instruction_t* i);
  int    dragon_instruction_is_trap(const dragon_instruction_t* i);
  int    dragon_instruction_has_indirect_target(const dragon_instruction_t* i);
  size_t dragon_instruction_edges(const dragon_instruction_t* i);

  void dragon_instruction_each_branch(const dragon_instruction_t* i,
      void (*cb)(uint64_t addr, void* user), void* user);
  void dragon_instruction_each_callee(const dragon_instruction_t* i,
      void (*cb)(uint64_t addr, void* user), void* user);

  // -- Assembler ----------------------------------------------------------------

  typedef struct dragon_asm dragon_asm_t;

  dragon_asm_t* dragon_asm_create(dragon_architecture_t arch, const dragon_config_t* config);
  void          dragon_asm_destroy(dragon_asm_t* a);
  int           dragon_asm_valid(const dragon_asm_t* a);

  // Assemble source text to raw bytes. Returns a heap-allocated buffer that
  // the caller must free with dragon_bytes_free(). Returns NULL on failure.
  uint8_t* dragon_asm_assemble(dragon_asm_t* a, const char* source, size_t* out_len);

  // Free a buffer returned by dragon_asm_assemble.
  void dragon_bytes_free(uint8_t* bytes);

  // -- BasicBlock ----------------------------------------------------------------

  void     dragon_block_destroy(dragon_block_t* b);
  int      dragon_block_valid(const dragon_block_t* b);
  uint64_t dragon_block_start_address(const dragon_block_t* b);
  uint64_t dragon_block_terminator_address(const dragon_block_t* b);
  size_t   dragon_block_size(const dragon_block_t* b);      // instruction count
  size_t   dragon_block_byte_size(const dragon_block_t* b);

  void dragon_block_each_instruction(const dragon_block_t* b,
      void (*cb)(const dragon_instruction_t*, void* user), void* user);
  void dragon_block_each_successor(const dragon_block_t* b,
      void (*cb)(uint64_t addr, void* user), void* user);

  // -- Function 

  void     dragon_function_destroy(dragon_function_t* f);
  int      dragon_function_valid(const dragon_function_t* f);
  uint64_t dragon_function_start_address(const dragon_function_t* f);
  size_t   dragon_function_num_blocks(const dragon_function_t* f);
  size_t   dragon_function_num_instructions(const dragon_function_t* f);
  size_t   dragon_function_edges(const dragon_function_t* f);
  size_t   dragon_function_byte_size(const dragon_function_t* f);
  size_t   dragon_function_cyclomatic_complexity(const dragon_function_t* f);

  void dragon_function_each_block(const dragon_function_t* f,
      void (*cb)(const dragon_block_t*, void* user), void* user);

  // -- String helper -------------------------------------------------------------

  // Free a C string returned by any dragon function whose documentation says
  // "free with dragon_cstr_free".  Do NOT use on static strings.
  void dragon_cstr_free(char* s);

  // Free a uint64_t array returned by any dragon function whose
  // documentation says "free with dragon_u64_array_free" (e.g.
  // dragon_read_table_targets, dragon_slice_expr_enumerate_values).
  void dragon_u64_array_free(uint64_t* arr);

  // -- IGNIL opcodes -------------------------------------------------------------

  // Mirror of ignil::Opcode.  Numerical values are guaranteed to match.
  typedef enum {
      DRAGON_IGNIL_COPY  = 0,
      DRAGON_IGNIL_LOAD  = 1,
      DRAGON_IGNIL_STORE = 2,
      DRAGON_IGNIL_ADD   = 3,
      DRAGON_IGNIL_SUB   = 4,
      DRAGON_IGNIL_NEG   = 5,
      DRAGON_IGNIL_MUL   = 6,
      DRAGON_IGNIL_SDIV  = 7,
      DRAGON_IGNIL_UDIV  = 8,
      DRAGON_IGNIL_SMOD  = 9,
      DRAGON_IGNIL_UMOD  = 10,
      DRAGON_IGNIL_AND   = 11,
      DRAGON_IGNIL_OR    = 12,
      DRAGON_IGNIL_XOR   = 13,
      DRAGON_IGNIL_NOT   = 14,
      DRAGON_IGNIL_SHL   = 15,
      DRAGON_IGNIL_SHR   = 16,
      DRAGON_IGNIL_SAR   = 17,
      DRAGON_IGNIL_ZEXT  = 18,
      DRAGON_IGNIL_SEXT  = 19,
      DRAGON_IGNIL_TRUNC = 20,
      DRAGON_IGNIL_EQ    = 21,
      DRAGON_IGNIL_NEQ   = 22,
      DRAGON_IGNIL_ULT   = 23,
      DRAGON_IGNIL_ULE   = 24,
      DRAGON_IGNIL_UGT   = 25,
      DRAGON_IGNIL_UGE   = 26,
      DRAGON_IGNIL_SLT   = 27,
      DRAGON_IGNIL_SLE   = 28,
      DRAGON_IGNIL_SGT   = 29,
      DRAGON_IGNIL_SGE   = 30,
      DRAGON_IGNIL_JMP   = 31,
      DRAGON_IGNIL_CJMP  = 32,
      DRAGON_IGNIL_CALL  = 33,
      DRAGON_IGNIL_RET   = 34,
      DRAGON_IGNIL_UNDEF = 35,
      // Appended after UNDEF, not interleaved with ADD/SUB/MUL above where
      // they'd read more naturally - see ignil::Opcode's own doc comment
      // for why new opcodes always go at the end of this mirror.
      DRAGON_IGNIL_FADD   = 36,
      DRAGON_IGNIL_FSUB   = 37,
      DRAGON_IGNIL_FMUL   = 38,
      DRAGON_IGNIL_FDIV   = 39,
      DRAGON_IGNIL_SITOFP = 40,
      DRAGON_IGNIL_FPTOSI = 41,
      DRAGON_IGNIL_OPAQUE = 42,
  } dragon_ignil_opcode_t;

  // Returns a static string for the opcode mnemonic (e.g. "ADD", "COPY").
  const char* dragon_ignil_opcode_name(dragon_ignil_opcode_t op);

  // -- IGNIL block ---------------------------------------------------------------

  // Borrowed pointer into the graph - valid while the owning graph is alive.
  // No destroy needed.
  typedef struct dragon_ignil_block dragon_ignil_block_t;

  // Returns NULL if no IGNIL block exists for this address.
  const dragon_ignil_block_t* dragon_graph_get_ignil_block(
      const dragon_graph_t* g, uint64_t addr);

  size_t   dragon_ignil_block_size(const dragon_ignil_block_t* b);
  uint64_t dragon_ignil_block_address(const dragon_ignil_block_t* b);

  // Render the whole block as a multi-line string.  Caller must free with dragon_cstr_free.
  char* dragon_ignil_block_to_string(const dragon_ignil_block_t* b);

  // Render one op (by 0-based index) as a string.  Caller must free with dragon_cstr_free.
  // Returns NULL if index >= block size.
  char* dragon_ignil_block_op_to_string(const dragon_ignil_block_t* b, size_t index);

  // Iterate ops; callback receives machine address, opcode, and 0-based index.
  void dragon_ignil_block_each_op(
      const dragon_ignil_block_t* b,
      void (*cb)(uint64_t op_addr, dragon_ignil_opcode_t opcode, size_t index, void* user),
      void* user);

  // Machine addresses of the instructions the lifter had no semantics for.
  // Their register and flag results are UNDEF in the block, but an UNDEF that
  // later dies is invisible and a memory-only effect leaves no op at all, so a
  // consumer that needs the block to be a complete account of the code checks
  // this list. Writes at most `cap` addresses to `out` (which may be NULL when
  // cap is 0) and returns the full count.
  size_t dragon_ignil_block_unlifted(const dragon_ignil_block_t* b,
                                     uint64_t* out, size_t cap);

  // -- Disassembler: trace lifting -------------------------------------------------

  // Lifts an arbitrary linear sequence of already-decoded instructions
  // straight to IGNIL, bypassing CFG/function/block validity analysis - see
  // Disassembler::liftTrace. `instructions` is an array of borrowed pointers
  // (e.g. from dragon_graph_each_instruction / dragon_graph_get_instruction),
  // consulted in the order given; they need not be contiguous or come from
  // the same graph, as long as they were decoded for the same architecture
  // as `d`. Returns an empty block for RISC-V (no IGNIL lifter yet) or an
  // empty trace.
  //
  // Returns an OWNED ignil block that must be destroyed with
  // dragon_ignil_block_destroy - NOT the same as blocks returned by
  // dragon_graph_get_ignil_block, which are borrowed from the graph and must
  // never be destroyed.
  dragon_ignil_block_t* dragon_disasm_lift_trace(
      const dragon_disasm_t* d,
      const dragon_instruction_t* const* instructions,
      size_t count);

  // Destroys a block returned by dragon_disasm_lift_trace. Do NOT call this
  // on a block returned by dragon_graph_get_ignil_block.
  void dragon_ignil_block_destroy(dragon_ignil_block_t* b);

  // -- IGNIL peephole simplifier ---------------------------------------------------

  // Peephole-simplifies `b`: forward constant folding/propagation, algebraic
  // identity/annihilator elimination, no-op width-conversion elimination, and
  // dead-Temp elimination, run to a fixed point (bounded by max_iterations -
  // 0 selects the library default of 8). Block-local only: does not cross
  // into predecessor/successor blocks, and never removes a Reg-defining op
  // even if apparently unused within the block (a Reg may be live-out).
  //
  // Every out_* pointer may be NULL if that count isn't wanted. When non-NULL
  // they report: constants folded, algebraic identities applied, dead ops
  // removed, and fixed-point iterations actually run (see
  // ignil::SimplifyStats).
  //
  // Returns an OWNED block - destroy with dragon_ignil_block_destroy, same as
  // a block from dragon_disasm_lift_trace, never dragon_graph_get_ignil_block.
  dragon_ignil_block_t* dragon_ignil_simplify_block(
      const dragon_ignil_block_t* b, int max_iterations,
      size_t* out_constants_folded, size_t* out_identities_applied,
      size_t* out_ops_removed, size_t* out_iterations);

  // -- IGNIL dead-store elimination ------------------------------------------------

  // One register in the IGNIL register address space: `offset` is its byte
  // position, `width` its bit width. Sub-registers share their parent's offset
  // and differ only in width (RAX {0,64}, EAX {0,32}, AX {0,16}, AL {0,8},
  // AH {1,8}). See dragon::ignil::Reg.
  typedef struct {
      uint32_t offset;
      uint8_t  width;
  } dragon_ignil_reg_t;

  // Removes dead register and flag stores from `b` by byte-precise backward
  // liveness: a value written to a register that is overwritten before it is
  // ever read, and is not live on exit, carries no information, so the op
  // producing it is dropped. Overlapping sub-registers alias correctly (writing
  // AX kills AL and AH but leaves the rest of RAX live). Unlike
  // dragon_ignil_simplify_block this DOES remove Reg-defining ops, which is
  // what collapses VM-protector junk. Dead Temps go too, so a machine
  // instruction whose only live effect was the removed register write
  // disappears entirely.
  //
  // Side-effecting ops (STORE/CALL/JMP/CJMP/RET) are never removed, and a store
  // is dropped only when every byte it clobbers is dead.
  //
  // `arch` selects the register file used to resolve which bytes a 32-bit write
  // zero-extends over - pass the architecture `b` was lifted for. Getting it
  // wrong (or passing DRAGON_ARCH_UNKNOWN) falls back to assuming an 8-byte
  // parent, which is correct for x86-64 GPRs and AArch64 W registers but not
  // for AArch64 S registers, which alias the 16-byte V registers.
  //
  // `live_out` names the registers observable after the block:
  //   - NULL (with live_out_count 0) means "assume everything is live on exit".
  //     A store is then removed only when provably overwritten within this
  //     block before any read, which needs no ABI knowledge and is always safe.
  //   - a non-NULL array means precisely those registers are live out, allowing
  //     more aggressive elimination (e.g. a RET-terminated block whose live-out
  //     is just the ABI return plus callee-saved registers). Correctness then
  //     rests on the caller supplying a sound live-out set.
  //
  // out_ops_removed may be NULL if the count isn't wanted.
  //
  // Returns an OWNED block - destroy with dragon_ignil_block_destroy, same as
  // a block from dragon_disasm_lift_trace, never dragon_graph_get_ignil_block.
  dragon_ignil_block_t* dragon_ignil_dead_store_eliminate(
      const dragon_ignil_block_t* b,
      dragon_architecture_t arch,
      const dragon_ignil_reg_t* live_out, size_t live_out_count,
      size_t* out_ops_removed);

  // -- SliceExpr -----------------------------------------------------------------

  typedef enum {
      DRAGON_SLICE_CONST   = 0,
      DRAGON_SLICE_SYM_REG = 1,
      DRAGON_SLICE_BINOP   = 2,
      DRAGON_SLICE_UNARYOP = 3,
      DRAGON_SLICE_LOAD    = 4,
      DRAGON_SLICE_UNDEF   = 5,
  } dragon_slice_type_t;

  // Owned handle.  Root and child handles must each be destroyed independently.
  typedef struct dragon_slice_expr dragon_slice_expr_t;

  void                  dragon_slice_expr_destroy(dragon_slice_expr_t* e);
  dragon_slice_type_t   dragon_slice_expr_type(const dragon_slice_expr_t* e);

  // Caller must free the returned string with dragon_cstr_free.
  char* dragon_slice_expr_to_string(const dragon_slice_expr_t* e);

  // Lower a SliceExpr through Z3 and return the Z3 bitvector expression as a
  // string. Only available when the library is built with -DDRAGON_USE_Z3=ON.
  // Caller must free with dragon_cstr_free.
#ifdef DRAGON_WITH_Z3
  char* dragon_slice_expr_to_z3_string(const dragon_slice_expr_t* e);

  // Enumerate concrete 64-bit values `e` can take (see
  // slice::enumeratedValues). Constructs and owns its own Z3 context
  // internally - there is no way to pass extra Z3 assertions across this
  // boundary, unlike the C++ API's optional `constraints` parameter; use the
  // C++ API directly if you need that.
  //   max_values: 0 selects the library default (256).
  //   sorted:     non-zero sorts results ascending (library default: sorted).
  //   out_count:  number of values written to the returned array (may be 0).
  // Returns an OWNED array - free with dragon_u64_array_free. Never NULL
  // (returns a zero-length allocation when there are no solutions), except
  // on a null `e`.
  uint64_t* dragon_slice_expr_enumerate_values(const dragon_slice_expr_t* e,
                                               size_t max_values, int sorted,
                                               size_t* out_count);

  // Solve for a single concrete value (see slice::solveUnique). Returns 1
  // and writes *out_value if exactly one model exists, 0 otherwise
  // (unsatisfiable, more than one model, or a null `e`/`out_value`).
  int dragon_slice_expr_solve_unique(const dragon_slice_expr_t* e,
                                     uint64_t* out_value);
#endif

  // DRAGON_SLICE_CONST
  uint64_t dragon_slice_expr_const_value(const dragon_slice_expr_t* e);
  uint8_t  dragon_slice_expr_const_width(const dragon_slice_expr_t* e);

  // DRAGON_SLICE_SYM_REG
  uint32_t    dragon_slice_expr_symreg_offset(const dragon_slice_expr_t* e);
  uint8_t     dragon_slice_expr_symreg_width(const dragon_slice_expr_t* e);
  // Returns a pointer into internal storage - valid while the expr is alive.
  // Empty string ("") when no name was set.
  const char* dragon_slice_expr_symreg_name(const dragon_slice_expr_t* e);

  // DRAGON_SLICE_BINOP / DRAGON_SLICE_UNARYOP - shared opcode accessor
  dragon_ignil_opcode_t dragon_slice_expr_opcode(const dragon_slice_expr_t* e);

  // DRAGON_SLICE_BINOP - caller must destroy returned handles.
  dragon_slice_expr_t* dragon_slice_expr_left(const dragon_slice_expr_t* e);
  dragon_slice_expr_t* dragon_slice_expr_right(const dragon_slice_expr_t* e);

  // DRAGON_SLICE_UNARYOP - caller must destroy returned handle.
  dragon_slice_expr_t* dragon_slice_expr_operand(const dragon_slice_expr_t* e);

  // DRAGON_SLICE_LOAD - caller must destroy the address handle.
  dragon_slice_expr_t* dragon_slice_expr_load_addr(const dragon_slice_expr_t* e);
  uint8_t              dragon_slice_expr_load_width(const dragon_slice_expr_t* e);

  // -- BackwardSlicer ------------------------------------------------------------

  typedef struct dragon_slicer dragon_slicer_t;

  // max_blocks caps how many inter-block steps the slicer takes (0 ≤ default = 5).
  dragon_slicer_t* dragon_slicer_create(int max_blocks);
  void             dragon_slicer_destroy(dragon_slicer_t* s);

  // Slice a register backwards through the CFG starting at block_addr.
  // reg_offset and reg_width identify the architectural register in the IGNIL
  // register address space (see x86IGNILRegs.hpp for x86 constants, or
  // armIGNILRegs.hpp for AArch64 constants).
  // reg_name is an optional human-readable label carried into SymReg results
  // when the value cannot be resolved (NULL or "" means no name).
  // Returns an owned SliceExpr; caller must destroy with dragon_slice_expr_destroy.
  dragon_slice_expr_t* dragon_slicer_slice_reg(
      const dragon_slicer_t* s,
      const dragon_graph_t*  g,
      uint64_t    block_addr,
      uint32_t    reg_offset,
      uint8_t     reg_width,
      const char* reg_name);

  // -- SwitchDetector --------------------------------------------------------------

  // Everything extracted from a detected jump-table pattern - mirrors
  // slice::SwitchCandidate. index_reg_offset/width identify the index
  // register in the IGNIL register address space (see x86IGNILRegs.hpp /
  // armIGNILRegs.hpp), the same convention dragon_slicer_slice_reg uses.
  typedef struct {
      uint64_t table_base;    // base address of the jump table in the image
      uint32_t entry_size;    // bytes per entry: 4 or 8
      uint32_t num_cases;     // 0 means the bounds check was not found
      uint32_t index_reg_offset;
      uint8_t  index_reg_width;
  } dragon_switch_candidate_t;

  // Inspect a backward-slice result (typically from dragon_slicer_slice_reg
  // on an indirect jump's target) and determine whether it is a jump-table
  // indirect branch - see slice::detectPossibleSwitch for the exact
  // recognition rules. Returns 1 and populates *out on a match (out->
  // num_cases == 0 means the pattern matched but the bounds guard wasn't
  // found), 0 otherwise (including a null jump_target/g/out).
  int dragon_detect_possible_switch(const dragon_slice_expr_t* jump_target,
                                    uint64_t block_addr,
                                    const dragon_graph_t* g,
                                    dragon_switch_candidate_t* out);

  // Read sw->num_cases pointer-sized little-endian entries from the jump
  // table described by `sw` out of `bytes` (a buffer starting at
  // `base_addr` in the binary's address space) - see
  // slice::readTableTargets. *out_count is 0 (and an empty allocation is
  // still returned, never NULL) when num_cases == 0 or the table extends
  // outside `bytes`. Returns an OWNED array - free with
  // dragon_u64_array_free.
  uint64_t* dragon_read_table_targets(const dragon_switch_candidate_t* sw,
                                      const uint8_t* bytes, size_t bytes_len,
                                      uint64_t base_addr, size_t* out_count);

  // -- LLVMLifter ---------------------------------------------------------------

  typedef struct dragon_llvm_lifter dragon_llvm_lifter_t;

  // Borrowed static string: LLVM linked into this library, not the system opt.
  const char* dragon_llvm_version(void);

  dragon_llvm_lifter_t* dragon_llvm_lifter_create(dragon_architecture_t arch,
                                                  const char* module_name);
  void dragon_llvm_lifter_destroy(dragon_llvm_lifter_t* l);

  // Lift one function. Returns 1 on success, 0 if any IGNIL block is missing.
  int  dragon_llvm_lifter_lift(dragon_llvm_lifter_t* l,
                               const dragon_function_t* fn,
                               const dragon_graph_t* g);

  // Context-sensitive finite path, not an all-path graph. Bodies are borrowed
  // during this call and may be NULL. transfer: 0=next, 1=call, 2=return.
  typedef struct {
    const dragon_ignil_block_t* body;
    uint64_t address;
    uint64_t next_address;
    uint32_t transfer;
    uint64_t return_address;
    uint32_t stack_adjustment;
  } dragon_llvm_path_step_t;
  int dragon_llvm_lifter_lift_path(dragon_llvm_lifter_t* l,
                                   const dragon_llvm_path_step_t* steps,
                                   size_t count, const char* name);

  // Dump textual LLVM IR. Caller must free with dragon_cstr_free.
  char* dragon_llvm_lifter_ir(const dragon_llvm_lifter_t* l);

  void dragon_llvm_lifter_run_mem2reg(dragon_llvm_lifter_t* l);
  void dragon_llvm_lifter_run_inst_combine(dragon_llvm_lifter_t* l);
  void dragon_llvm_lifter_run_gvn(dragon_llvm_lifter_t* l);
  void dragon_llvm_lifter_run_dce(dragon_llvm_lifter_t* l);

  // Import verified textual LLVM IR; failure leaves the previous module intact.
  // In-process PassBuilder pipeline and LLVM verifier. 1=success, 0=failure.
  // On failure the module is unchanged. Optional *error is an owned diagnostic
  // (NULL on success); release it with dragon_cstr_free. Not semantic proofs.
  int dragon_llvm_lifter_run_pass_pipeline(dragon_llvm_lifter_t* l,
                                           const char* pipeline, char** error);
  int dragon_llvm_lifter_verify(const dragon_llvm_lifter_t* l, char** error);
  int dragon_llvm_lifter_load_ir(dragon_llvm_lifter_t* l, const char* text);
  // Post-O2 fixed-trip scalar chain reroll. Returns number of loops created.
  size_t dragon_llvm_lifter_run_loop_reroll(dragon_llvm_lifter_t* l);

  // -- FLIRT signatures (dragon::sigs) --------------------------------------------

  typedef struct dragon_sigdb dragon_sigdb_t;

  dragon_sigdb_t* dragon_sigdb_create(void);
  void            dragon_sigdb_destroy(dragon_sigdb_t* db);

  // Loads every .pat file directly inside dir (not recursive). Files that
  // fail to parse are silently skipped - compare signature_count() before
  // and after to see how much was actually loaded.
  void dragon_sigdb_load_directory(dragon_sigdb_t* db, const char* dir);

  // Loads a single .pat file. No-op if it can't be parsed.
  void dragon_sigdb_load_file(dragon_sigdb_t* db, const char* path);

  size_t dragon_sigdb_signature_count(const dragon_sigdb_t* db);

  // The CRC16 variant dragon-tales' signature format uses: reflected,
  // polynomial 0xA001 (CRC-16/ARC), init 0xFFFF, no final XOR. Caveat: this
  // could not be verified against a real IDA/FLAIR-generated .pat file (see
  // SignatureMatcher's class doc) - self-consistent with this codebase's own
  // parser/matcher, but the first thing to check if a real signature
  // database is loaded and nothing ever matches.
  uint16_t dragon_sigs_crc16(const uint8_t* data, size_t len);

  // Tries every signature in db against bytes, which must begin at the
  // candidate function's address. Returns 1 and fills the out params if any
  // signature matches (the first match's primary name), 0 otherwise. Any out
  // pointer may be NULL to ignore that field. *out_name receives an owned
  // string - caller must free with dragon_cstr_free.
  int dragon_sigdb_match_at(const dragon_sigdb_t* db,
                            const uint8_t* bytes, size_t len,
                            uint64_t address,
                            uint64_t* out_address, char** out_name,
                            uint32_t* out_length);

  // Tries every address in entry_points against every signature in db.
  // image/image_base describe the byte region entry_points fall within.
  // Unlike match_at, every name a matching signature defines is reported (a
  // module can bundle more than one function/offset under one pattern), so
  // one entry point may produce more than one callback invocation. `name` is
  // borrowed - valid only for the duration of the callback.
  void dragon_sigdb_match_entries(
      const dragon_sigdb_t* db,
      const uint8_t* image, size_t image_len, uint64_t image_base,
      const uint64_t* entry_points, size_t num_entry_points,
      void (*cb)(uint64_t address, const char* name, uint32_t length, void* user),
      void* user);


  // -- IGNIL symbolic execution --------------------------------------------
  //
  // Executes IGNIL ops over Z3 bitvectors: seed registers and memory
  // (concretely or symbolically), run a block, then either read a value back
  // as an expression or ask the solver about it. Two things this is for:
  // recovering the input that makes a checksum come out to a target value,
  // and resolving a computed jump to the concrete addresses it can reach.
  //
  // Only available when the library is built with -DDRAGON_USE_Z3=ON.
#ifdef DRAGON_WITH_Z3

  // Owned handle on a Z3 expression. Destroy every handle you are given.
  typedef struct dragon_symexpr dragon_symexpr_t;
  // Owned handle on an executor, its state and its solver.
  typedef struct dragon_symexec dragon_symexec_t;
  // Owned handle on one run's outcome.
  typedef struct dragon_symrun dragon_symrun_t;
  // Owned handle on a satisfying assignment.
  typedef struct dragon_solution dragon_solution_t;
  // Owned handle on a snapshot of an executor's register/memory/constraint
  // state.
  typedef struct dragon_symstate dragon_symstate_t;
  typedef struct dragon_call_trace dragon_call_trace_t;
  typedef struct dragon_state_summary dragon_state_summary_t;
  // Owned handle on the list of locations two states disagree on.
  typedef struct dragon_symdiff dragon_symdiff_t;

  // Lower a recovered return expression to a typed pure LLVM function.
  // Every free dependency must be one of the distinct named arguments. No
  // unknown symbols/opaque calls are filled with zero or solver model values.
  // Returns 0 for unsupported expressions, mixed contexts or invalid handles.
  int dragon_llvm_lifter_lift_expression(dragon_llvm_lifter_t* l,
                                        const dragon_symexpr_t* expression,
                                        const dragon_symexpr_t* const* arguments,
                                        size_t count, const char* name);
  typedef struct dragon_expression_call {
    const dragon_symexpr_t *result;
    const char *function;
    const dragon_symexpr_t *const *arguments;
    size_t argument_count;
  } dragon_expression_call_t;
  int dragon_llvm_lifter_lift_expression_calls(
          dragon_llvm_lifter_t *l, const dragon_symexpr_t *expression,
          const dragon_symexpr_t *const *arguments, size_t count,
          const char *name, const dragon_expression_call_t *calls,
          size_t call_count);

  // while (continuation) carried = next; returns the header state as a struct.
  int dragon_llvm_lifter_lift_loop_region(dragon_llvm_lifter_t *l,
      const dragon_symexpr_t *const *inputs, size_t input_count,
      const dragon_symexpr_t *const *carried,
      const dragon_symexpr_t *const *next, size_t carried_count,
      const dragon_symexpr_t *continuation, const char *name);


  // Build a pure scalar-return loop. No restrictions on counter/step/latch.
  // Initial state uses inputs; next/continuation/return also use carried PHIs.
  // entry_guard and otherwise are either both NULL or both supplied.
  int dragon_llvm_lifter_lift_loop_function(dragon_llvm_lifter_t *l,
      const dragon_symexpr_t *const *inputs, size_t input_count,
      const dragon_symexpr_t *const *carried,
      const dragon_symexpr_t *const *initial,
      const dragon_symexpr_t *const *next, size_t carried_count,
      const dragon_symexpr_t *continuation, const dragon_symexpr_t *returned,
      const dragon_symexpr_t *entry_guard, const dragon_symexpr_t *otherwise,
      const char *name);

  // Opt-in, all-memory symbolic effect tracking. Enable before executing a
  // path. Captured/concrete memory is not imported; initial bytes are unknown.
  // Snapshot/restore includes arrays and events; merge/diff rejects this mode.
  int dragon_symexec_enable_memory_effects(dragon_symexec_t* e);
  size_t dragon_symexec_memory_effect_count(const dragon_symexec_t* e);
  int dragon_symexec_memory_effect(const dragon_symexec_t* e, size_t index,
                                  int* is_store, uint64_t* pc, unsigned* width);
  // Returned expressions are owned and retain the executor/context.
  dragon_symexpr_t* dragon_symexec_memory_effect_address(const dragon_symexec_t* e, size_t index);
  dragon_symexpr_t* dragon_symexec_memory_effect_value(const dragon_symexec_t* e, size_t index);
  dragon_symexpr_t* dragon_symexec_effect_memory(const dragon_symexec_t* e, int initial);
  dragon_symexpr_t* dragon_symexec_effect_constraints(const dragon_symexec_t* e);
  // Export actual ordered loads/stores plus optional return (NULL = void).
  // pointer_arguments[i] exports a BV64 source symbol as ptr, without noalias.
  // The caller must validate path completeness/preconditions. Ordinary valid
  // nonvolatile memory only; no atomic/concurrency/MMIO/fault equivalence.
  int dragon_llvm_lifter_lift_effects(dragon_llvm_lifter_t* l,
                                    const dragon_symexec_t* e,
                                    const dragon_symexpr_t* expression,
                                    const dragon_symexpr_t* const* arguments,
                                    const int* pointer_arguments, size_t count,
                                    const char* name);

  // Mirror of ignil::ExecStatus.
  typedef enum {
      DRAGON_SYMEXEC_OK             = 0,
      DRAGON_SYMEXEC_MALFORMED_OP   = 1,
      DRAGON_SYMEXEC_UNSUPPORTED_OP = 2,
      DRAGON_SYMEXEC_SOLVER_FAILURE = 3,
  } dragon_symexec_status_t;

  // Mirror of ignil::ExitKind.
  typedef enum {
      DRAGON_SYMEXIT_FALLTHROUGH       = 0,
      DRAGON_SYMEXIT_JUMP              = 1,
      DRAGON_SYMEXIT_CONDITIONAL_JUMP  = 2,
      DRAGON_SYMEXIT_CALL              = 3,
      DRAGON_SYMEXIT_RETURN            = 4,
      DRAGON_SYMEXIT_ERROR             = 5,
  } dragon_symexec_exit_t;

  // Mirror of ignil::SymbolicOptions. Every field takes the library default
  // when left at 0, so a zero-initialised struct means "all defaults". The
  // three flags are tri-state for that reason: 0 keeps the default, 1 turns
  // the behaviour on, -1 turns it off.
  typedef struct {
      unsigned solver_timeout_ms;          // 0 -> 5000
      size_t   max_address_solutions;      // 0 -> 64
      size_t   max_branch_targets;         // 0 -> 256
      int      zero_extend_on_32bit_write; // 0 default (on), 1 on, -1 off
      int      symbolize_unmapped_reads;   // 0 default (on), 1 on, -1 off
      int      stop_at_terminator;         // 0 default (on), 1 on, -1 off
  } dragon_symexec_options_t;

  // `opts` may be NULL for the defaults.
  dragon_symexec_t* dragon_symexec_create(const dragon_symexec_options_t* opts);
  void              dragon_symexec_destroy(dragon_symexec_t* e);
  // Drop all register/memory/constraint state; keeps the options.
  void              dragon_symexec_reset(dragon_symexec_t* e);

  // Default on: use native analysis-host RDTSC/RDTSCP; 0 selects symbolic.
  // Kept outside options_t so the existing C options struct ABI is unchanged.
  void dragon_symexec_set_host_timestamps(dragon_symexec_t *e, int enabled);
  int dragon_symexec_host_timestamps(const dragon_symexec_t *e);

  // Watched byte-level reads-before-writes, for resolved loop boundaries.
  // kind: 0 register, 1 memory. flags: live-in=1, read=2, written=4.
  typedef struct dragon_state_range {
    uint32_t kind;
    uint64_t key;
    uint64_t bytes;
  } dragon_state_range_t;
  int dragon_symexec_begin_access_trace(dragon_symexec_t *e,
                                        const dragon_state_range_t *ranges,
                                        size_t count);
  int dragon_symexec_end_access_trace(dragon_symexec_t *e,
      void (*cb)(uint32_t kind, uint64_t key, uint32_t flags, void *user),
      void *user);
  // Analysis binding only: 32-bit register ranges preserve adjacent bytes.
  dragon_symexpr_t *dragon_symexec_symbolize_range(dragon_symexec_t *e,
      uint32_t kind, uint64_t key, uint8_t width, const char *name);

  // -- state snapshots. Copying the state is far cheaper than rebuilding it,
  // so an analysis that runs many blocks from the same seeded machine should
  // seed once, snapshot, and restore before each block rather than creating a
  // fresh executor every time. A snapshot keeps its executor alive by itself,
  // exactly as an expression handle does.
  dragon_symstate_t* dragon_symexec_snapshot(const dragon_symexec_t* e);
  // Replaces the executor's state wholesale. `s` must come from this executor.
  void               dragon_symexec_restore(dragon_symexec_t* e,
                                            const dragon_symstate_t* s);
  void               dragon_symstate_destroy(dragon_symstate_t* s);

  // Joins `incoming` into the snapshot `into`: every register or memory byte
  // the two disagree on becomes, in `into`, a fresh variable named after `tag`
  // (`top@<tag>!m<addr>:<bits>` / `top@<tag>!r<offset>:<bits>`). Returns the
  // locations that were symbolised, as a diff list whose values are the new
  // variables; an empty list means `incoming` added nothing, which is the
  // fixed-point test of a worklist exploration. Bytes an earlier merge under
  // the same tag already symbolised are left alone, so repeated merges into
  // one snapshot converge. Both snapshots must come from the same executor.
  // Returns NULL on a NULL argument.
  /* Exact guarded physical-state join; returns the projection violation. */
  dragon_symexpr_t *
  dragon_symstate_join_guarded(dragon_symstate_t *into,
                               const dragon_symstate_t *incoming,
                               const dragon_symexpr_t *condition);

  dragon_symdiff_t*  dragon_symstate_merge(dragon_symstate_t* into,
                                           const dragon_symstate_t* incoming,
                                           const char* tag);

  // Complete-invocation deterministic state transformer. Queries must be proved
  // independently before apply. Opaque/undefined observations are excluded.
  // Snapshot before begin. At each matched return, detach records that path's
  // definite writes; sibling snapshots keep collecting independently. Build
  // only after all local returns and a proved exact physical-state join. Build
  // errors are owned strings freed by dragon_cstr_free. Trace, summary and
  // expression handles keep their executor/context alive; destroy each.
  // read_control_memory is only for actual RET targets, not ordinary data.
  dragon_call_trace_t *dragon_symexec_begin_call_trace(dragon_symexec_t *e);
  void dragon_symexec_detach_call_trace(dragon_symexec_t *e,
                                        const dragon_call_trace_t *trace);
  int dragon_call_trace_cacheable(const dragon_call_trace_t *trace);
  void dragon_call_trace_destroy(dragon_call_trace_t *trace);
  dragon_symexpr_t *
  dragon_symexec_read_control_memory(const dragon_symexec_t *e, uint64_t addr,
                                     uint8_t width);
  dragon_state_summary_t *dragon_state_summary_build(
          const dragon_symstate_t *before, const dragon_symstate_t *after,
          dragon_call_trace_t *trace, uint64_t return_slot, const char *tag,
          const dragon_symexpr_t *const *from,
          const dragon_symexpr_t *const *to, size_t count, char **error);
  void dragon_state_summary_destroy(dragon_state_summary_t *summary);
  dragon_symexpr_t *
  dragon_state_summary_projection(const dragon_state_summary_t *summary);
  dragon_symexpr_t *
  dragon_state_summary_applicability(const dragon_state_summary_t *summary,
                                     const dragon_symexec_t *e);
  int dragon_state_summary_apply(const dragon_state_summary_t *summary,
                                 dragon_symexec_t *e);
  size_t
  dragon_state_summary_input_count(const dragon_state_summary_t *summary);
  size_t
  dragon_state_summary_output_count(const dragon_state_summary_t *summary);

  // -- machine setup. Registers are named by their IGNIL register-space byte
  // offset and bit width - the values in x86IGNILRegs.hpp / armIGNILRegs.hpp.
  void dragon_symexec_set_register(dragon_symexec_t *e, uint32_t offset,
                                   uint8_t width, uint64_t value);
  // Binds the register to a fresh variable and returns it. `name` may be NULL
  // for an auto-generated one.
  dragon_symexpr_t* dragon_symexec_symbolize_register(
      dragon_symexec_t* e, uint32_t offset, uint8_t width, const char* name);

  // Exact fresh naming of a computed register, including its stored copies.
  // No execution is skipped. NULL on reused name or memory-effect mode.
  dragon_symexpr_t* dragon_symexec_bind_register_value(
      dragon_symexec_t* e, uint32_t offset, uint8_t width, const char* name);

  void dragon_symexec_map_memory(dragon_symexec_t* e, uint64_t address,
                                 const uint8_t* data, size_t len);
  // Fills [address, address+size) with per-byte variables named
  // `<name>[0]`..`<name>[size-1]`; dragon_solution_bytes reads them back.
  dragon_symexpr_t* dragon_symexec_symbolize_memory(
      dragon_symexec_t* e, uint64_t address, uint64_t size, const char* name);

  // Constrains the rest of the run. `c` must be a boolean expression.
  void dragon_symexec_assume(dragon_symexec_t* e, const dragon_symexpr_t* c);

  // Parse SMT-LIB assertions into this executor's Z3 context and return their
  // conjunction without assuming it. Declarations must match existing input
  // names/sorts. NULL on invalid input; the returned expression owns its
  // context.
  dragon_symexpr_t *dragon_symexec_parse_condition(dragon_symexec_t *e,
                                                   const char *script);


  // Import one BV expression serialized as (= |dragon!result| expression).
  // Exactly one assertion, a free BV marker and no recursive marker use are
  // required. This does not assume anything or alter machine state.
  dragon_symexpr_t *dragon_symexec_parse_expression(dragon_symexec_t *e,
                                                    const char *script);

  // Domain-scoped pure DAG simplification. Never assumes domain into state.
  // Bounded proof-only guard projection; timeout retains unmatched expressions.
  dragon_symexpr_t *dragon_symexec_simplify_projection(dragon_symexec_t *e,
      const dragon_symexpr_t *expression, const dragon_symexpr_t *domain,
      const dragon_symexpr_t *const *inputs, size_t input_count,
      unsigned timeout_ms, size_t *queries, size_t *rewrites);

  // Rewrite physical state from a proved equality, retaining its path
  // assumptions. 1 rewritten, 0 equality not implied, -1 invalid/unknown.
  int dragon_symexec_specialize_equality(dragon_symexec_t *e,
                                         const dragon_symexpr_t *equality);

  // Writes an expression rather than a host integer. The memory form stores
  // little-endian, as many bytes as the expression is wide. `x` must be a
  // bitvector.
  void dragon_symexec_write_register(dragon_symexec_t* e, uint32_t offset,
                                     uint8_t width, const dragon_symexpr_t* x);
  void dragon_symexec_write_memory(dragon_symexec_t* e, uint64_t address,
                                   const dragon_symexpr_t* x);

  // Suffix for the variables a run invents for loads it could not resolve.
  // They are named after the op's address and position in the run, so running
  // one block in two contexts hands out the same names; set a tag per context
  // to keep them apart. NULL or "" restores the untagged names.
  void dragon_symexec_set_fresh_tag(dragon_symexec_t* e, const char* tag);

  // Make an OPAQUE op (CPUID=0, RDTSC=1, RDTSCP=2) return concrete `results`
  // instead of a symbol, so a concolic trace stays concrete through an
  // anti-tamper CPUID. `selector` identifies the invocation from its operands:
  // for CPUID it is (leaf << 32) | (subleaf & 0xffffffff); for RDTSC/RDTSCP it
  // is 0. `results` are the per-result-index values (CPUID: EAX,EBX,ECX,EDX)
  // and `n` their count. Only matching ops are concretised; everything else
  // keeps the default symbolic behaviour.
  void dragon_symexec_set_concrete_opaque(dragon_symexec_t* e, uint32_t kind,
                                          uint64_t selector,
                                          const uint64_t* results, size_t n);

  // The register / memory value as a host integer, when it is a literal. These
  // are the cheap form of read + evaluate for a location expected to be
  // concrete: no expression handle, no solver. Return 0 (and leave *out alone)
  // when the value is symbolic or wider than 64 bits.
  int dragon_symexec_concrete_register(const dragon_symexec_t* e,
                                       uint32_t offset, uint8_t width,
                                       uint64_t* out);
  int dragon_symexec_concrete_memory(const dragon_symexec_t* e, uint64_t address,
                                     uint8_t width, uint64_t* out);

  // -- expressions. Every one of these returns an owned handle.
  dragon_symexpr_t* dragon_symexec_const(const dragon_symexec_t* e,
                                         uint64_t value, uint8_t width);
  dragon_symexpr_t* dragon_symexec_read_register(const dragon_symexec_t* e,
                                                 uint32_t offset, uint8_t width);
  dragon_symexpr_t* dragon_symexec_read_memory(const dragon_symexec_t* e,
                                               uint64_t address, uint8_t width);

  // -- state diffing. Everything whose value differs from the snapshot
  // `before`, coalesced into the widest runs that came from one written value.
  // This is the batch form of reading every candidate location back and
  // comparing: one call, plus one expression handle per location that actually
  // changed, instead of a read per location.
  dragon_symdiff_t* dragon_symexec_diff(const dragon_symexec_t* e,
                                        const dragon_symstate_t* before);
  void              dragon_symdiff_destroy(dragon_symdiff_t* d);
  size_t            dragon_symdiff_count(const dragon_symdiff_t* d);
  // Describes entry `index`. `kind` is 0 for a register (`key` is an IGNIL
  // register-space byte offset) and 1 for memory (`key` is an address);
  // `width` is the run's width in bits. Returns 0 on a bad index.
  int               dragon_symdiff_entry(const dragon_symdiff_t* d, size_t index,
                                         int* kind, uint64_t* key, uint8_t* width);
  // Owned expression handle for entry `index`, or NULL.
  dragon_symexpr_t* dragon_symdiff_value(const dragon_symdiff_t* d, size_t index);

  void      dragon_symexpr_destroy(dragon_symexpr_t* x);
  // Caller must free with dragon_cstr_free.
  char*     dragon_symexpr_to_string(const dragon_symexpr_t* x);
  // Bit width of a bitvector expression; 0 for a boolean.
  // A complete SMT-LIB 2 script - declarations included - asserting
  // `(= |dragon!result| x)` for a bitvector, or `x` itself for a boolean. This
  // is the form another Z3 binding can parse back into a term without being
  // told what the free variables are. Caller must free with dragon_cstr_free.
  char*     dragon_symexpr_to_smt2(const dragon_symexpr_t* x);
  // Writes *out and returns 1 if the expression folds to a literal of at most
  // 64 bits.
  int       dragon_symexpr_as_u64(const dragon_symexpr_t* x, uint64_t* out);
  uint8_t   dragon_symexpr_width(const dragon_symexpr_t* x);
  int       dragon_symexpr_is_bool(const dragon_symexpr_t* x);

  typedef enum {
      // bitvector x bitvector -> bitvector
      DRAGON_SYMOP_ADD = 0,
      DRAGON_SYMOP_SUB = 1,
      DRAGON_SYMOP_MUL = 2,
      DRAGON_SYMOP_AND = 3,
      DRAGON_SYMOP_OR  = 4,
      DRAGON_SYMOP_XOR = 5,
      // bitvector x bitvector -> boolean
      DRAGON_SYMOP_EQ  = 6,
      DRAGON_SYMOP_NE  = 7,
      DRAGON_SYMOP_ULT = 8,
      DRAGON_SYMOP_ULE = 9,
      DRAGON_SYMOP_UGT = 10,
      DRAGON_SYMOP_UGE = 11,
      DRAGON_SYMOP_SLT = 12,
      DRAGON_SYMOP_SLE = 13,
      DRAGON_SYMOP_SGT = 14,
      DRAGON_SYMOP_SGE = 15,
      // boolean x boolean -> boolean
      DRAGON_SYMOP_BOOL_AND = 16,
      DRAGON_SYMOP_BOOL_OR  = 17,
      DRAGON_SYMOP_IMPLIES  = 18,
  } dragon_symop_t;

  // Returns NULL if the operands' sorts do not fit the operator.
  dragon_symexpr_t* dragon_symexpr_binop(dragon_symop_t op,
                                         const dragon_symexpr_t* a,
                                         const dragon_symexpr_t* b);
  // Boolean negation. Returns NULL if `a` is not boolean.
  dragon_symexpr_t* dragon_symexpr_not(const dragon_symexpr_t* a);
  // Conditional expression. Requires a boolean condition, equal arm sorts,
  // and one shared Z3 context. Returns NULL on invalid arguments.
  dragon_symexpr_t* dragon_symexpr_ite(const dragon_symexpr_t* condition,
                                      const dragon_symexpr_t* yes,
                                      const dragon_symexpr_t* no);

  // -- execution.  Returns an owned run handle, or NULL on a NULL argument.
  dragon_symrun_t* dragon_symexec_run(dragon_symexec_t* e,
                                      const dragon_ignil_block_t* b);
  void dragon_symrun_destroy(dragon_symrun_t* r);

  // Exact IGNIL-op continuation: no native-instruction prefix is replayed.
  dragon_symrun_t* dragon_symexec_run_from(dragon_symexec_t* e,
                                           const dragon_ignil_block_t* b, size_t first_op);
  void dragon_symexec_set_fork_reads(dragon_symexec_t* e, int enabled);
  typedef struct dragon_read_choice dragon_read_choice_t;
  dragon_read_choice_t* dragon_symrun_read_choice(const dragon_symrun_t* r);
  void dragon_read_choice_destroy(dragon_read_choice_t* c);
  dragon_symexpr_t* dragon_read_choice_expression(const dragon_read_choice_t* c);
  size_t dragon_read_choice_count(const dragon_read_choice_t* c);
  size_t dragon_read_choice_next_op(const dragon_read_choice_t* c);
  uint64_t dragon_read_choice_address(const dragon_read_choice_t* c);
  uint64_t dragon_read_choice_slot(const dragon_read_choice_t* c);
  int dragon_read_choice_is_value(const dragon_read_choice_t* c);
  uint64_t dragon_read_choice_value(const dragon_read_choice_t* c, size_t i);
  dragon_symexpr_t* dragon_read_choice_guard(const dragon_read_choice_t* c, size_t i);
  int dragon_symexec_choose_read(dragon_symexec_t* e, const dragon_read_choice_t* c, size_t i);


  dragon_symexec_status_t dragon_symrun_status(const dragon_symrun_t* r);
  dragon_symexec_exit_t   dragon_symrun_exit(const dragon_symrun_t* r);
  // 1 when the run succeeded and every successor and memory access resolved
  // exactly - i.e. the successor list is the complete set of reachable
  // addresses. 0 when some of it had to be left open; see the warnings.
  int    dragon_symrun_complete(const dragon_symrun_t* r);
  // NULL when the run succeeded; else caller frees with dragon_cstr_free.
  char*  dragon_symrun_error(const dragon_symrun_t* r);

  void   dragon_symrun_stats(const dragon_symrun_t* r, size_t* out_ops_executed,
                             size_t* out_solver_queries,
                             size_t* out_addresses_concretized);

  // Actual native host samples used by this run. Each row is one dynamic
  // instruction, not one OPAQUE result. kind: RDTSC=1, RDTSCP=2.
  size_t dragon_symrun_host_timestamp_count(const dragon_symrun_t *r);
  int dragon_symrun_host_timestamp(const dragon_symrun_t *r, size_t index,
                                   uint64_t *out_address, uint32_t *out_kind,
                                   uint64_t *out_tsc, uint32_t *out_aux);

  size_t dragon_symrun_successor_count(const dragon_symrun_t* r);
  // Reads successor `index`. `out_taken` reports the true-side edge of a
  // CJMP. Returns 0 if `index` is out of range.
  int    dragon_symrun_successor(const dragon_symrun_t* r, size_t index,
                                 uint64_t* out_address, int* out_taken);
  // The guard under which that successor is reached. Owned handle.
  dragon_symexpr_t* dragon_symrun_successor_condition(const dragon_symrun_t* r,
                                                      size_t index);

  // -- accesses the run could not resolve: a LOAD or STORE whose address had
  // too many satisfying values to expand. The LOAD produced a fresh variable
  // and the STORE was dropped (each with a warning); a caller rebuilding code
  // from the run needs the access itself.
  size_t dragon_symrun_unresolved_count(const dragon_symrun_t* r);
  // Describes entry `index`: whether it is a store, the machine address of the
  // op, and the access width in bits. Returns 0 on a bad index.
  int    dragon_symrun_unresolved(const dragon_symrun_t* r, size_t index,
                                  int* out_is_store, uint64_t* out_op_address,
                                  uint8_t* out_width);
  // The address expression of entry `index`. Owned handle.
  dragon_symexpr_t* dragon_symrun_unresolved_address(const dragon_symrun_t* r,
                                                     size_t index);
  // The value stored, or the variable standing in for the value loaded. Owned
  // handle.
  dragon_symexpr_t* dragon_symrun_unresolved_value(const dragon_symrun_t* r,
                                                   size_t index);

  size_t dragon_symrun_warning_count(const dragon_symrun_t* r);
  // Caller frees the returned string with dragon_cstr_free.
  char*  dragon_symrun_warning(const dragon_symrun_t* r, size_t index,
                               uint64_t* out_address);

  // -- solver queries. The tri-state ones return 1 (yes), 0 (no) or -1 (the
  // solver timed out or gave up) - never a guess.
  int dragon_symexec_is_satisfiable(dragon_symexec_t* e,
                                    const dragon_symexpr_t* c);
  int dragon_symexec_proves(dragon_symexec_t* e, const dragon_symexpr_t* c);

  // Writes *out and returns 1 only if the path constraints force exactly one
  // value for `x` - the "is this obfuscated expression really a constant?"
  // query.
  int dragon_symexec_evaluate(dragon_symexec_t* e, const dragon_symexpr_t* x,
                              uint64_t* out);

  // Up to `max` distinct satisfying values of `x`, written to `out`. Returns
  // how many were written. *out_exhaustive (may be NULL) is set to 1 only if
  // the enumeration ran out of values rather than hitting `max`.
  size_t dragon_symexec_enumerate(dragon_symexec_t* e,
                                  const dragon_symexpr_t* x, uint64_t* out,
                                  size_t max, int* out_exhaustive);

  // Solves the path constraints, plus `goal` when it is non-NULL. Returns
  // NULL if there is no satisfying assignment.
  dragon_solution_t* dragon_symexec_solve(dragon_symexec_t* e,
                                          const dragon_symexpr_t* goal);
  void dragon_solution_destroy(dragon_solution_t* s);

  // Value bound to one symbol. Returns 0 if the model does not bind it.
  int    dragon_solution_value(const dragon_solution_t* s, const char* symbol,
                               uint64_t* out);
  // Bytes of a symbolised memory region, in address order. Writes at most
  // `cap` bytes and returns the region's full size (which may exceed `cap`);
  // returns 0 if no region of that name was symbolised.
  size_t dragon_solution_bytes(const dragon_solution_t* s, const char* region,
                               uint8_t* out, size_t cap);
  // Every bound symbol. `name` is borrowed - valid only during the callback.
  void   dragon_solution_each(const dragon_solution_t* s,
                              void (*cb)(const char* name, uint64_t value,
                                         void* user),
                              void* user);

#endif // DRAGON_WITH_Z3

  #ifdef __cplusplus
  }
  #endif