# C API

Include `dragon_c.h` and link against `libdragon_c`.

```c
#include <dragon_c.h>
#include <stdio.h>
```

---

## Configuration

`dragon_config_t` is an opaque handle that groups syntax, disassembly strategy,
and the LLVM target knobs `cpu` and `features`.
It must be destroyed with `dragon_config_destroy` when no longer needed.

```c
dragon_config_t* config = dragon_config_create(DRAGON_SYNTAX_INTEL,
                                               DRAGON_STRATEGY_LINEAR_SWEEP);

// Inspect current settings
dragon_syntax_t   s = dragon_config_syntax(config);
dragon_strategy_t r = dragon_config_strategy(config);

dragon_config_destroy(config);
```

### Targeting a specific CPU or ISA revision

`dragon_config_set_cpu` and `dragon_config_set_features` forward strings
directly to LLVM's `MCSubtargetInfo`. Both default to `""` (LLVM "generic"
baseline). Set them before passing the config to a disassembler or assembler.

```c
// ARM32 — enable BX/BLX (ARMv4T, not present in the generic baseline)
dragon_config_t* config = dragon_config_create(DRAGON_SYNTAX_INTEL,
                                               DRAGON_STRATEGY_LINEAR_SWEEP);
dragon_config_set_cpu(config, "arm926ej-s");   // ARMv5TEJ
dragon_disasm_t* dis = dragon_disasm_create(DRAGON_ARCH_ARM32, config);
dragon_config_destroy(config);

// ARM32 — use feature flags instead of a CPU name
dragon_config_t* config = dragon_config_create(DRAGON_SYNTAX_INTEL,
                                               DRAGON_STRATEGY_LINEAR_SWEEP);
dragon_config_set_features(config, "+v7,+neon");
dragon_disasm_t* dis = dragon_disasm_create(DRAGON_ARCH_ARM32, config);
dragon_config_destroy(config);

// RISC-V 64 — multiply, atomics, compressed extensions
dragon_config_t* config = dragon_config_create(DRAGON_SYNTAX_INTEL,
                                               DRAGON_STRATEGY_LINEAR_SWEEP);
dragon_config_set_features(config, "+m,+a,+c");
dragon_disasm_t* dis = dragon_disasm_create(DRAGON_ARCH_RISCV64, config);
dragon_config_destroy(config);
```

### Diagnostic logging

`dragon_config_set_logging` toggles the library's internal diagnostics to
`stderr` (off by default); `dragon_config_logging` reads the current setting.

```c
dragon_config_set_logging(config, 1);        // enable
int on = dragon_config_logging(config);       // query
```

**API reference**

| Function | Description |
|---|---|
| `dragon_config_create(syntax, strategy)` | Create a config; destroy with `dragon_config_destroy` |
| `dragon_config_syntax(c)` | Get the output syntax (`DRAGON_SYNTAX_INTEL` / `DRAGON_SYNTAX_ATT`) |
| `dragon_config_strategy(c)` | Get the disassembly strategy |
| `dragon_config_set_cpu(c, "cortex-a8")` | Set CPU name |
| `dragon_config_cpu(c)` | Get current CPU name (`""` = generic) |
| `dragon_config_set_features(c, "+v4t")` | Set feature string |
| `dragon_config_features(c)` | Get current feature string |
| `dragon_config_set_logging(c, enabled)` | Enable (`1`) or disable (`0`) diagnostics to `stderr` |
| `dragon_config_logging(c)` | Get the current logging flag |

---

## Disassembler

Create a `dragon_disasm_t` from an architecture and a configuration, then call
`dragon_disasm_disassemble` for each buffer you want to decode.
The returned graph must be destroyed when done.

```c
// x86-64: nop; ret
static const uint8_t code[] = { 0x90, 0xC3 };

dragon_config_t*  config = dragon_config_create(DRAGON_SYNTAX_INTEL,
                                                DRAGON_STRATEGY_LINEAR_SWEEP);
dragon_disasm_t*  dis    = dragon_disasm_create(DRAGON_ARCH_X86_64, config);
dragon_config_destroy(config);   // config is copied into the disassembler

if (!dragon_disasm_valid(dis)) { /* handle error */ }

dragon_graph_t* graph = dragon_disasm_disassemble(dis, code, sizeof(code),
                                                  /*base_address=*/0x1000);

dragon_disasm_destroy(dis);

if (!graph) { /* handle error */ }

// -- iterate instructions via callback
void print_insn(const dragon_instruction_t* insn, void* user) {
    printf("0x%llx  %s\n",
           (unsigned long long)dragon_instruction_address(insn),
           dragon_instruction_disassembly(insn));
}

dragon_graph_each_instruction(graph, print_insn, NULL);

dragon_graph_destroy(graph);
```

### Instruction flags

```c
void inspect_insn(const dragon_instruction_t* insn, void* user) {
    if (dragon_instruction_is_call(insn))
        printf("  call at 0x%llx\n", dragon_instruction_address(insn));
    if (dragon_instruction_is_jump(insn))
        printf("  jump at 0x%llx\n", dragon_instruction_address(insn));
    if (dragon_instruction_is_return(insn))
        printf("  ret  at 0x%llx\n", dragon_instruction_address(insn));
}

dragon_graph_each_instruction(graph, inspect_insn, NULL);
```

### Raw bytes of an instruction

```c
void print_bytes(const dragon_instruction_t* insn, void* user) {
    size_t len;
    const uint8_t* b = dragon_instruction_bytes(insn, &len);
    for (size_t i = 0; i < len; i++)
        printf("%02x ", b[i]);
    printf("\n");
}
```

### Instruction accessors

A `dragon_instruction_t` is a borrowed pointer into the graph's listing — it
needs no destroy and stays valid while the owning graph is alive. The
mnemonic, operands, disassembly and pattern strings it returns are also
borrowed (owned by the instruction); do not free them.

| Function | Returns | Notes |
|---|---|---|
| `dragon_instruction_address(i)` | `uint64_t` | Machine address |
| `dragon_instruction_size(i)` | `uint8_t` | Encoded length in bytes |
| `dragon_instruction_mnemonic(i)` | `const char*` (borrowed) | E.g. `"mov"` |
| `dragon_instruction_operands(i)` | `const char*` (borrowed) | Operand text only |
| `dragon_instruction_disassembly(i)` | `const char*` (borrowed) | Full `mnemonic operands` text |
| `dragon_instruction_pattern(i)` | `const char*` (borrowed) | Normalized pattern string |
| `dragon_instruction_bytes(i, out_len)` | `const uint8_t*` (borrowed) | Raw encoded bytes |
| `dragon_instruction_chromosome_mask(i, out_len)` | `const uint8_t*` (borrowed) | Per-byte "variable vs. fixed" mask used by signature matching |
| `dragon_instruction_is_block_start(i)` | `int` (0/1) | Begins a basic block |
| `dragon_instruction_is_function_start(i)` | `int` (0/1) | Begins a function |
| `dragon_instruction_is_prologue(i)` | `int` (0/1) | Part of a recognized prologue |
| `dragon_instruction_is_return(i)` | `int` (0/1) | A return |
| `dragon_instruction_is_call(i)` | `int` (0/1) | A call |
| `dragon_instruction_is_jump(i)` | `int` (0/1) | A branch |
| `dragon_instruction_is_conditional(i)` | `int` (0/1) | A conditional branch |
| `dragon_instruction_is_trap(i)` | `int` (0/1) | A trap/`int3`-style instruction |
| `dragon_instruction_has_indirect_target(i)` | `int` (0/1) | Branches/calls through a register or memory |
| `dragon_instruction_edges(i)` | `size_t` | Number of outgoing control-flow edges |
| `dragon_instruction_each_branch(i, cb, user)` | — | Callback `(uint64_t addr, void* user)` per branch target |
| `dragon_instruction_each_callee(i, cb, user)` | — | Callback `(uint64_t addr, void* user)` per call target |

### Recursive traversal

```c
dragon_config_t* config = dragon_config_create(DRAGON_SYNTAX_INTEL,
                                               DRAGON_STRATEGY_RECURSIVE_TRAVERSAL);
dragon_disasm_t* dis = dragon_disasm_create(DRAGON_ARCH_X86_64, config);
dragon_config_destroy(config);
```

### Disassemble vs. analyze

`dragon_disasm_disassemble` only decodes instructions. `dragon_disasm_analyze`
decodes *and* runs architecture-specific analysis — basic-block and function
discovery, plus IGNIL lifting — returning a fully populated graph. Use it
whenever you need blocks, functions, or IGNIL blocks (the backward slicer and
LLVM lifter both require it). Both take the same arguments and both return a
graph the caller must destroy.

```c
dragon_graph_t* graph = dragon_disasm_analyze(dis, code, sizeof(code), 0x1000);
// graph now has instructions, blocks, functions, and IGNIL blocks
dragon_graph_destroy(graph);
```

---

## Loader

`dragon_loader_t` parses an ELF or PE/COFF image — from a file or from bytes
already in memory — and exposes its sections, ELF `PT_LOAD` segments, symbols,
entry point and image base, with the architecture auto-detected from the
header. `dragon_loader_disassemble` goes straight from a loaded image to a
populated graph without having to carve out a `.text` blob or name the
architecture.

Both constructors return `NULL` on failure; when `err` is non-NULL a
NUL-terminated reason of at most `err_cap` bytes is written. The loader owns
every name, section-bytes and segment-bytes pointer it hands out — all are
borrowed and valid only while the loader is alive. Destroy it with
`dragon_loader_destroy`.

```c
char err[256];
dragon_loader_t* ld = dragon_load_file("a.out", err, sizeof(err));
if (!ld) { fprintf(stderr, "load failed: %s\n", err); return 1; }

printf("format=%d arch=%d 64-bit=%d image_base=0x%llx\n",
       dragon_loader_format(ld), dragon_loader_architecture(ld),
       dragon_loader_is_64bit(ld),
       (unsigned long long)dragon_loader_image_base(ld));

if (dragon_loader_has_entry(ld))
    printf("entry=0x%llx\n", (unsigned long long)dragon_loader_entry(ld));

// Sections (name borrowed; permission/placement out-params may be NULL)
for (size_t i = 0; i < dragon_loader_section_count(ld); ++i) {
    uint64_t addr, vsize; int r, w, x;
    const char* name = dragon_loader_section(ld, i, &addr, &vsize, &r, &w, &x);
    printf("  %-16s 0x%llx (%llu bytes) %c%c%c\n", name,
           (unsigned long long)addr, (unsigned long long)vsize,
           r ? 'r' : '-', w ? 'w' : '-', x ? 'x' : '-');
}

// Symbols
for (size_t i = 0; i < dragon_loader_symbol_count(ld); ++i) {
    uint64_t addr, size; dragon_symbol_kind_t kind; int imp, exp;
    const char* name = dragon_loader_symbol(ld, i, &addr, &size, &kind, &imp, &exp);
    printf("  %s @0x%llx kind=%d%s%s\n", name, (unsigned long long)addr,
           kind, imp ? " [import]" : "", exp ? " [export]" : "");
}

// Straight to a populated graph (config may be NULL for defaults)
dragon_graph_t* graph = dragon_loader_disassemble(ld, NULL);
printf("%zu instructions\n", dragon_graph_size(graph));

dragon_graph_destroy(graph);
dragon_loader_destroy(ld);
```

### Sections vs. segments

`dragon_loader_section_*` reports the section headers; `dragon_loader_segment_*`
reports ELF `PT_LOAD` segments — what the system loader actually maps (named
`"LOAD0"`, `"LOAD1"`, …), and the only layout left when a protector strips the
section headers. The segment accessors follow the same conventions as the
section accessors; PE images have no segments, so `dragon_loader_segment_count`
returns 0 for them.

```c
for (size_t i = 0; i < dragon_loader_segment_count(ld); ++i) {
    uint64_t addr, vsize; int r, w, x;
    dragon_loader_segment(ld, i, &addr, &vsize, &r, &w, &x);

    size_t len;
    const uint8_t* bytes = dragon_loader_segment_bytes(ld, i, &len);
    // ... bytes[0..len) are the segment's file contents (borrowed) ...
}
```

### Reading the virtual address space

`dragon_loader_read_virtual` copies up to `cap` bytes from the image's virtual
address space into `out`, returning the number of bytes written — or 0 if the
range `[addr, addr+cap)` is unmapped. Handy for following a pointer discovered
during analysis without tracking which section it lands in.

```c
uint8_t buf[16];
size_t n = dragon_loader_read_virtual(ld, 0x401000, buf, sizeof(buf));
```

**API summary**

| Function | Returns | Notes |
|---|---|---|
| `dragon_load_file(path, err, err_cap)` | **owned** `dragon_loader_t*` | NULL on failure; reason written to `err` |
| `dragon_load_bytes(bytes, len, err, err_cap)` | **owned** `dragon_loader_t*` | Loads an image already in memory |
| `dragon_loader_destroy(l)` | — | |
| `dragon_loader_format(l)` | `dragon_format_t` | `UNKNOWN` / `ELF` / `PE` |
| `dragon_loader_architecture(l)` | `dragon_architecture_t` | Detected from the header |
| `dragon_loader_is_64bit(l)` | `int` (0/1) | |
| `dragon_loader_has_entry(l)` / `dragon_loader_entry(l)` | `int` / `uint64_t` | `entry` is valid only when `has_entry` is 1 |
| `dragon_loader_image_base(l)` | `uint64_t` | |
| `dragon_loader_section_count(l)` | `size_t` | |
| `dragon_loader_section(l, i, out_addr, out_vsize, out_r, out_w, out_x)` | `const char*` (borrowed) | NULL for an out-of-range index; out-params may be NULL |
| `dragon_loader_section_bytes(l, i, out_len)` | `const uint8_t*` (borrowed) | File bytes of the section |
| `dragon_loader_segment_count(l)` | `size_t` | 0 for PE |
| `dragon_loader_segment(l, i, out_addr, out_vsize, out_r, out_w, out_x)` | `const char*` (borrowed) | ELF `PT_LOAD` segments (`"LOAD0"`, …) |
| `dragon_loader_segment_bytes(l, i, out_len)` | `const uint8_t*` (borrowed) | File bytes of the segment |
| `dragon_loader_symbol_count(l)` | `size_t` | |
| `dragon_loader_symbol(l, i, out_addr, out_size, out_kind, out_imported, out_exported)` | `const char*` (borrowed) | NULL for an out-of-range index; out-params may be NULL |
| `dragon_loader_read_virtual(l, addr, out, cap)` | `size_t` | Bytes written, or 0 if unmapped |
| `dragon_loader_disassemble(l, config)` | **owned** `dragon_graph_t*` | Disassembles every executable section; `config` may be NULL |

`dragon_symbol_kind_t` is `DRAGON_SYMBOL_UNKNOWN`, `_FUNCTION`, `_OBJECT`,
`_SECTION` or `_FILE`.

---

## Graph: blocks and functions

```c
// Look up a single instruction by address
const dragon_instruction_t* insn = dragon_graph_get_instruction(graph, 0x1000);
if (insn)
    printf("%s\n", dragon_instruction_disassembly(insn));

// Iterate block start addresses
void on_block(uint64_t addr, void* user) {
    printf("block @ 0x%llx\n", (unsigned long long)addr);
}
dragon_graph_each_block_address(graph, on_block, NULL);

// Get a block and walk its instructions
dragon_block_t* bb = dragon_graph_get_block(graph, 0x1000);
if (dragon_block_valid(bb)) {
    printf("block size: %zu instructions\n", dragon_block_size(bb));
    dragon_block_each_instruction(bb, print_insn, NULL);
}
dragon_block_destroy(bb);

// Get a function
dragon_function_t* fn = dragon_graph_get_function(graph, 0x1000);
if (dragon_function_valid(fn)) {
    printf("blocks:       %zu\n", dragon_function_num_blocks(fn));
    printf("instructions: %zu\n", dragon_function_num_instructions(fn));
    printf("cyclomatic:   %zu\n", dragon_function_cyclomatic_complexity(fn));
}
dragon_function_destroy(fn);
```

`dragon_graph_get_instruction` and `dragon_graph_get_ignil_block` return
borrowed pointers (no destroy, valid while the graph lives), whereas
`dragon_graph_get_block` and `dragon_graph_get_function` return heap-allocated
views the caller must destroy with `dragon_block_destroy` /
`dragon_function_destroy`.

An empty graph can also be created directly with `dragon_graph_create(arch)` —
useful as a container the trace lifter or other producers fill in — and must
be destroyed the same way.

**Graph API summary**

| Function | Returns | Notes |
|---|---|---|
| `dragon_graph_create(arch)` | **owned** `dragon_graph_t*` | Empty graph for `arch` |
| `dragon_graph_destroy(g)` | — | |
| `dragon_graph_size(g)` | `size_t` | Instruction count |
| `dragon_graph_empty(g)` | `int` (0/1) | |
| `dragon_graph_get_instruction(g, addr)` | `const dragon_instruction_t*` (borrowed) | NULL if none at `addr` |
| `dragon_graph_get_block(g, addr)` | **owned** `dragon_block_t*` | Destroy with `dragon_block_destroy` |
| `dragon_graph_get_function(g, addr)` | **owned** `dragon_function_t*` | Destroy with `dragon_function_destroy` |
| `dragon_graph_get_ignil_block(g, addr)` | `const dragon_ignil_block_t*` (borrowed) | NULL if none at `addr` |
| `dragon_graph_each_instruction(g, cb, user)` | — | Callback `(const dragon_instruction_t*, void*)` |
| `dragon_graph_each_block_address(g, cb, user)` | — | Callback `(uint64_t addr, void*)` |
| `dragon_graph_each_function_address(g, cb, user)` | — | Callback `(uint64_t addr, void*)` |

**BasicBlock API summary**

| Function | Returns | Notes |
|---|---|---|
| `dragon_block_destroy(b)` | — | |
| `dragon_block_valid(b)` | `int` (0/1) | |
| `dragon_block_start_address(b)` | `uint64_t` | |
| `dragon_block_terminator_address(b)` | `uint64_t` | Address of the block's last instruction |
| `dragon_block_size(b)` | `size_t` | Instruction count |
| `dragon_block_byte_size(b)` | `size_t` | Size in bytes |
| `dragon_block_each_instruction(b, cb, user)` | — | Callback `(const dragon_instruction_t*, void*)` |
| `dragon_block_each_successor(b, cb, user)` | — | Callback `(uint64_t addr, void*)` |

**Function API summary**

| Function | Returns | Notes |
|---|---|---|
| `dragon_function_destroy(f)` | — | |
| `dragon_function_valid(f)` | `int` (0/1) | |
| `dragon_function_start_address(f)` | `uint64_t` | |
| `dragon_function_num_blocks(f)` | `size_t` | |
| `dragon_function_num_instructions(f)` | `size_t` | |
| `dragon_function_edges(f)` | `size_t` | CFG edge count |
| `dragon_function_byte_size(f)` | `size_t` | |
| `dragon_function_cyclomatic_complexity(f)` | `size_t` | |
| `dragon_function_each_block(f, cb, user)` | — | Callback `(const dragon_block_t*, void*)` |

---

## Assembler

```c
dragon_config_t* config = dragon_config_create(DRAGON_SYNTAX_INTEL,
                                               DRAGON_STRATEGY_LINEAR_SWEEP);
dragon_asm_t* asm_ = dragon_asm_create(DRAGON_ARCH_X86_64, config);
dragon_config_destroy(config);

if (!dragon_asm_valid(asm_)) { /* handle error */ }

size_t   out_len;
uint8_t* bytes = dragon_asm_assemble(asm_, "nop\nret\n", &out_len);
if (!bytes) { /* assembly failed */ }

for (size_t i = 0; i < out_len; i++)
    printf("%02x ", bytes[i]);
// 90 c3

dragon_bytes_free(bytes);
dragon_asm_destroy(asm_);
```

### AT&T syntax

```c
dragon_config_t* config = dragon_config_create(DRAGON_SYNTAX_ATT,
                                               DRAGON_STRATEGY_LINEAR_SWEEP);
dragon_asm_t* asm_ = dragon_asm_create(DRAGON_ARCH_X86_64, config);
dragon_config_destroy(config);
```

---

## IGNIL blocks

`dragon_disasm_analyze` populates both the CFG and the IGNIL blocks in the
returned graph. Use `dragon_graph_get_ignil_block` to retrieve a block by
address (borrowed pointer — no destroy needed, valid while the graph is alive).

```c
// nop; cmp rax, rbx; ret
static const uint8_t code[] = { 0x90, 0x48, 0x39, 0xD8, 0xC3 };

dragon_config_t* config = dragon_config_create(DRAGON_SYNTAX_INTEL,
                                               DRAGON_STRATEGY_LINEAR_SWEEP);
dragon_disasm_t* dis    = dragon_disasm_create(DRAGON_ARCH_X86_64, config);
dragon_config_destroy(config);

dragon_graph_t* graph = dragon_disasm_analyze(dis, code, sizeof(code), 0x1000);
dragon_disasm_destroy(dis);

const dragon_ignil_block_t* ib = dragon_graph_get_ignil_block(graph, 0x1000);
if (ib) {
    // Render the whole block
    char* s = dragon_ignil_block_to_string(ib);
    printf("%s", s);
    dragon_cstr_free(s);

    // Iterate ops
    void on_op(uint64_t addr, dragon_ignil_opcode_t opc, size_t idx, void* u) {
        printf("  [%zu] @0x%llx  %s\n", idx, (unsigned long long)addr,
               dragon_ignil_opcode_name(opc));
    }
    dragon_ignil_block_each_op(ib, on_op, NULL);
}

dragon_graph_destroy(graph);
```

**IGNIL block API summary**

| Function | Returns | Notes |
|---|---|---|
| `dragon_graph_get_ignil_block(g, addr)` | borrowed `const dragon_ignil_block_t*` | NULL if no IGNIL block at addr |
| `dragon_ignil_block_address(b)` | `uint64_t` | Start address |
| `dragon_ignil_block_size(b)` | `size_t` | Op count |
| `dragon_ignil_block_to_string(b)` | `char*` (heap) | Free with `dragon_cstr_free` |
| `dragon_ignil_block_op_to_string(b, idx)` | `char*` (heap) | Single op; NULL if idx ≥ size |
| `dragon_ignil_block_each_op(b, cb, user)` | — | Callback receives addr, opcode, index |
| `dragon_ignil_opcode_name(opc)` | `const char*` (static) | E.g. `"ADD"`, `"COPY"` |

### Trace lifting

`dragon_disasm_lift_trace` lifts an arbitrary linear sequence of
already-decoded instructions straight to IGNIL — e.g. a captured execution
trace (Unicorn/QBDI/Frida/Intel PT) that isn't claimed to form a single
valid basic block or a coherent CFG. It bypasses `dragon_disasm_analyze`'s
CFG/function/block-validity checks entirely: each instruction is lifted
independently and the results concatenated in order, with no synthesized
fall-through terminator.

Unlike `dragon_graph_get_ignil_block`'s borrowed result, the returned block
is **owned by the caller** and must be destroyed with
`dragon_ignil_block_destroy` — never call that function on a block that came
from `dragon_graph_get_ignil_block` (borrowed, owned by the graph; doing so
double-frees it).

```c
dragon_graph_t* graph = dragon_disasm_disassemble(dis, code, sizeof(code), 0x1000);

// Collect borrowed instruction pointers to feed as a trace — here just the
// whole linear decode, but they could come from anywhere (e.g. addresses
// visited by a real emulator run), in any order, even non-contiguous.
const dragon_instruction_t* trace[/* count */];
size_t n = 0;
void collect(const dragon_instruction_t* i, void* user) {
    trace[n++] = i;
}
dragon_graph_each_instruction(graph, collect, NULL);

dragon_ignil_block_t* block = dragon_disasm_lift_trace(dis, trace, n);
char* s = dragon_ignil_block_to_string(block);
printf("%s", s);
dragon_cstr_free(s);

dragon_ignil_block_destroy(block);   // owned — NOT dragon_graph_get_ignil_block's block
dragon_graph_destroy(graph);
```

| Function | Returns | Notes |
|---|---|---|
| `dragon_disasm_lift_trace(d, instructions, count)` | **owned** `dragon_ignil_block_t*` | Empty block for RISC-V or an empty trace |
| `dragon_ignil_block_destroy(b)` | — | Only for blocks from `dragon_disasm_lift_trace` |

### Peephole simplification

`dragon_ignil_simplify_block` runs `ignil::simplifyBlock` to a fixed point:
constant folding/propagation, algebraic identity/annihilator elimination,
no-op width-conversion elimination, and dead-Temp elimination. It is
block-local only — it never crosses into predecessor/successor blocks, and
never removes a `Reg`-defining op even if apparently unused within the block
(a `Reg` may be live-out).

```c
dragon_ignil_block_t* block = dragon_disasm_lift_trace(dis, trace, n);

size_t folded, identities, removed, iterations;
dragon_ignil_block_t* simplified = dragon_ignil_simplify_block(
    block, /*max_iterations=*/0,   // 0 selects the library default (8)
    &folded, &identities, &removed, &iterations);

printf("folded=%zu identities=%zu removed=%zu iterations=%zu\n",
       folded, identities, removed, iterations);

char* s = dragon_ignil_block_to_string(simplified);
printf("%s", s);
dragon_cstr_free(s);

dragon_ignil_block_destroy(simplified);   // owned, independent of `block`
dragon_ignil_block_destroy(block);
```

| Function | Returns | Notes |
|---|---|---|
| `dragon_ignil_simplify_block(b, max_iterations, out_folded, out_identities, out_removed, out_iterations)` | **owned** `dragon_ignil_block_t*` | Every `out_*` pointer may be NULL; `max_iterations = 0` selects the default (8) |

### Unlifted instructions

A block is a faithful account of the code only if the lifter had semantics for
every instruction in it. `dragon_ignil_block_unlifted` reports the machine
addresses of the instructions it did not: their register and flag results are
`UNDEF`, but an `UNDEF` that later dies is invisible and a memory-only effect
leaves no op at all, so a consumer that needs completeness must check this
list. It writes at most `cap` addresses to `out` (which may be NULL when `cap`
is 0) and returns the full count — call it once with `cap == 0` to size the
array.

```c
size_t n = dragon_ignil_block_unlifted(ib, NULL, 0);
if (n) {
    uint64_t* addrs = malloc(n * sizeof(uint64_t));
    dragon_ignil_block_unlifted(ib, addrs, n);
    for (size_t i = 0; i < n; ++i)
        printf("unlifted @0x%llx\n", (unsigned long long)addrs[i]);
    free(addrs);
}
```

### Dead-store elimination

`dragon_ignil_dead_store_eliminate` removes dead register and flag stores by
byte-precise backward liveness: a value written to a register that is
overwritten before it is ever read, and is not live on exit, carries no
information, so the op producing it is dropped. Overlapping sub-registers alias
correctly (writing `AX` kills `AL` and `AH` but leaves the rest of `RAX`
live). Unlike `dragon_ignil_simplify_block` this *does* remove `Reg`-defining
ops — which is what collapses VM-protector junk — and a machine instruction
whose only live effect was the removed write disappears entirely. Side-effecting
ops (`STORE`/`CALL`/`JMP`/`CJMP`/`RET`) are never removed, and a store is
dropped only when every byte it clobbers is dead.

`arch` selects the register file used to resolve which bytes a 32-bit write
zero-extends over — pass the architecture the block was lifted for. `live_out`
names the registers observable after the block:

- `NULL` (with `live_out_count` 0) means "assume everything is live on exit":
  a store is removed only when provably overwritten within this block before
  any read, which needs no ABI knowledge and is always safe.
- a non-NULL array means precisely those registers are live out, enabling more
  aggressive elimination (e.g. a `RET`-terminated block whose live-out is the
  ABI return register plus the callee-saved set). Correctness then rests on the
  caller supplying a sound live-out set.

```c
// Everything live on exit — always safe, no ABI knowledge needed.
size_t removed;
dragon_ignil_block_t* lean = dragon_ignil_dead_store_eliminate(
    ib, DRAGON_ARCH_X86_64, NULL, 0, &removed);

// Or: only RAX (offset 0, width 64) is live out.
dragon_ignil_reg_t live_out[] = { { 0, 64 } };
dragon_ignil_block_t* leaner = dragon_ignil_dead_store_eliminate(
    ib, DRAGON_ARCH_X86_64, live_out, 1, &removed);

dragon_ignil_block_destroy(lean);
dragon_ignil_block_destroy(leaner);
```

`dragon_ignil_reg_t` names one register in the IGNIL register address space —
`offset` is its byte position, `width` its bit width — the same convention the
backward slicer uses (`RAX` is `{0, 64}`, `EAX` `{0, 32}`, `AL` `{0, 8}`,
`AH` `{1, 8}`).

| Function | Returns | Notes |
|---|---|---|
| `dragon_ignil_block_unlifted(b, out, cap)` | `size_t` | Full count; writes at most `cap` addresses (`out` may be NULL when `cap` is 0) |
| `dragon_ignil_dead_store_eliminate(b, arch, live_out, live_out_count, out_ops_removed)` | **owned** `dragon_ignil_block_t*` | `live_out` NULL means "all live"; `out_ops_removed` may be NULL |

---

## Backward slicer

`dragon_slicer_t` wraps `BackwardSlicer`. `dragon_slice_expr_t` is an owned
handle to a node in the expression tree; child handles (left, right, operand,
load_addr) are also owned and must each be destroyed independently.

```c
// Slice ZF backward starting from block 0x1000
dragon_slicer_t* slicer = dragon_slicer_create(/*max_blocks=*/5);

dragon_slice_expr_t* expr = dragon_slicer_slice_reg(
    slicer, graph,
    /*block_addr=*/0x1000,
    /*reg_offset=*/139,   // ZF offset
    /*reg_width =*/8,     // ZF is 8-bit in IGNIL
    /*reg_name  =*/"ZF");

// Render the whole expression
char* s = dragon_slice_expr_to_string(expr);
printf("%s\n", s);   // EQ(SUB(RAX:i64, RBX:i64), 0x0:i64)
dragon_cstr_free(s);

// Walk the tree
if (dragon_slice_expr_type(expr) == DRAGON_SLICE_BINOP) {
    dragon_ignil_opcode_t opc = dragon_slice_expr_opcode(expr);
    printf("opcode: %s\n", dragon_ignil_opcode_name(opc));

    dragon_slice_expr_t* left  = dragon_slice_expr_left(expr);
    dragon_slice_expr_t* right = dragon_slice_expr_right(expr);

    // left is another BINOP (SUB), right is a CONST
    if (dragon_slice_expr_type(right) == DRAGON_SLICE_CONST)
        printf("rhs: 0x%llx:i%d\n",
               (unsigned long long)dragon_slice_expr_const_value(right),
               (int)dragon_slice_expr_const_width(right));

    dragon_slice_expr_destroy(left);
    dragon_slice_expr_destroy(right);
}

dragon_slice_expr_destroy(expr);
dragon_slicer_destroy(slicer);
```

**SliceExpr API summary**

| Function | Type | Notes |
|---|---|---|
| `dragon_slice_expr_destroy(e)` | — | Must be called for every owned handle |
| `dragon_slice_expr_type(e)` | `dragon_slice_type_t` | CONST / SYM_REG / BINOP / UNARYOP / LOAD / UNDEF |
| `dragon_slice_expr_to_string(e)` | `char*` (heap) | Free with `dragon_cstr_free` |
| `dragon_slice_expr_const_value(e)` | `uint64_t` | CONST nodes only |
| `dragon_slice_expr_const_width(e)` | `uint8_t` | CONST nodes only |
| `dragon_slice_expr_symreg_offset(e)` | `uint32_t` | SYM_REG nodes only |
| `dragon_slice_expr_symreg_width(e)` | `uint8_t` | SYM_REG nodes only |
| `dragon_slice_expr_symreg_name(e)` | `const char*` (borrowed) | SYM_REG; `""` if no name was set |
| `dragon_slice_expr_opcode(e)` | `dragon_ignil_opcode_t` | BINOP / UNARYOP |
| `dragon_slice_expr_left(e)` | owned `dragon_slice_expr_t*` | BINOP |
| `dragon_slice_expr_right(e)` | owned `dragon_slice_expr_t*` | BINOP |
| `dragon_slice_expr_operand(e)` | owned `dragon_slice_expr_t*` | UNARYOP |
| `dragon_slice_expr_load_addr(e)` | owned `dragon_slice_expr_t*` | LOAD |
| `dragon_slice_expr_load_width(e)` | `uint8_t` | LOAD |

### Z3 string representation

Available when the library is built with `-DDRAGON_USE_Z3=ON`
(`DRAGON_WITH_Z3` is defined).

```c
#ifdef DRAGON_WITH_Z3
char* z3s = dragon_slice_expr_to_z3_string(expr);
printf("Z3: %s\n", z3s);   // (bvadd rax #x0000000000000004)
dragon_cstr_free(z3s);
#endif
```

The returned string is a heap-allocated Z3 expression in SMT-LIB2 format.
Free it with `dragon_cstr_free`. Returns `"undef"` for a null pointer.

### Value enumeration and unique-value solving

Also gated on `-DDRAGON_USE_Z3=ON`. Both functions construct and own their
Z3 context internally — there is no way to pass extra Z3 assertions across
the C boundary, unlike the C++ API's optional `constraints` parameter; use
the C++ API directly (`dragon::slice::enumeratedValues` /
`dragon::slice::solveUnique`) if you need that.

```c
#ifdef DRAGON_WITH_Z3
size_t count;
uint64_t* values = dragon_slice_expr_enumerate_values(
    expr, /*max_values=*/0, /*sorted=*/1, &count);   // 0 -> default cap (256)
for (size_t i = 0; i < count; ++i)
    printf("value[%zu] = 0x%llx\n", i, (unsigned long long)values[i]);
dragon_u64_array_free(values);

uint64_t unique;
if (dragon_slice_expr_solve_unique(expr, &unique))
    printf("unique value: 0x%llx\n", (unsigned long long)unique);
#endif
```

| Function | Returns | Notes |
|---|---|---|
| `dragon_slice_expr_enumerate_values(e, max_values, sorted, out_count)` | **owned** `uint64_t*` | Free with `dragon_u64_array_free`; never NULL except on a null `e` |
| `dragon_slice_expr_solve_unique(e, out_value)` | `int` | 1 and writes `*out_value` iff exactly one model exists |
| `dragon_u64_array_free(arr)` | — | Frees arrays from either function above (and from `dragon_read_table_targets`, see SwitchDetector) |

---

## SwitchDetector

Wraps `dragon::slice::detectPossibleSwitch` / `readTableTargets` — recognizes
a jump-table indirect-branch pattern from a backward-slice result (typically
the target of an indirect `JMP`, sliced with the backward slicer above) and
reads the concrete targets out of the table's raw bytes.

```c
dragon_slice_expr_t* jump_target = dragon_slicer_slice_reg(
    slicer, graph, block_addr, /*reg_offset=*/0, /*reg_width=*/64, "");

dragon_switch_candidate_t sw;
if (dragon_detect_possible_switch(jump_target, block_addr, graph, &sw)) {
    printf("table_base=0x%llx entry_size=%u num_cases=%u\n",
           (unsigned long long)sw.table_base, sw.entry_size, sw.num_cases);

    // `table_bytes`/`table_base_addr` describe a window of the binary's
    // image that contains the table (e.g. the whole .rodata section).
    size_t count;
    uint64_t* targets = dragon_read_table_targets(
        &sw, table_bytes, table_bytes_len, table_base_addr, &count);
    for (size_t i = 0; i < count; ++i)
        printf("case %zu -> 0x%llx\n", i, (unsigned long long)targets[i]);
    dragon_u64_array_free(targets);
}

dragon_slice_expr_destroy(jump_target);
```

`dragon_switch_candidate_t` is a plain value struct (not an opaque handle,
nothing to destroy):

```c
typedef struct {
    uint64_t table_base;       // base address of the jump table in the image
    uint32_t entry_size;       // bytes per entry: 4 or 8
    uint32_t num_cases;        // 0 means the bounds check was not found
    uint32_t index_reg_offset; // index register, same convention as
    uint8_t  index_reg_width;  // dragon_slicer_slice_reg's reg_offset/reg_width
} dragon_switch_candidate_t;
```

| Function | Returns | Notes |
|---|---|---|
| `dragon_detect_possible_switch(jump_target, block_addr, g, out)` | `int` | 1 and populates `*out` on a match; a matched `num_cases == 0` means the bounds guard wasn't found |
| `dragon_read_table_targets(sw, bytes, bytes_len, base_addr, out_count)` | **owned** `uint64_t*` | Free with `dragon_u64_array_free`; empty (not NULL) if `num_cases == 0` or the table falls outside `bytes` |

Not every indirect jump is a jump table — GCC and Clang often lower a
`switch` to a plain compare chain instead (no jump table at all) when the
case count is small or the cases aren't dense, in which case
`dragon_detect_possible_switch` correctly returns 0 and there's nothing
further to recover here.

---

## LLVMLifter

`dragon_llvm_lifter_t` wraps the C++ `LLVMLifter`. It must be destroyed with
`dragon_llvm_lifter_destroy` when no longer needed. `ir` strings are
heap-allocated and must be freed with `dragon_cstr_free`.

`graph` must come from `dragon_disasm_analyze` — IGNIL blocks must be present.

```c
static const uint8_t code[] = {
    0x55,                    // push rbp
    0x48, 0x89, 0xE5,        // mov  rbp, rsp
    0x48, 0x01, 0xD8,        // add  rax, rbx
    0x5D,                    // pop  rbp
    0xC3,                    // ret
};

dragon_config_t* config = dragon_config_create(DRAGON_SYNTAX_INTEL,
                                               DRAGON_STRATEGY_LINEAR_SWEEP);
dragon_disasm_t* dis    = dragon_disasm_create(DRAGON_ARCH_X86_64, config);
dragon_config_destroy(config);

dragon_graph_t*    graph  = dragon_disasm_analyze(dis, code, sizeof(code), 0x1000);
dragon_function_t* fn     = dragon_graph_get_function(graph, 0x1000);
dragon_disasm_destroy(dis);

dragon_llvm_lifter_t* lifter = dragon_llvm_lifter_create(DRAGON_ARCH_X86_64,
                                                          "my_module");

if (dragon_llvm_lifter_lift(lifter, fn, graph)) {
    // Raw IR
    char* ir = dragon_llvm_lifter_ir(lifter);
    printf("%s", ir);
    dragon_cstr_free(ir);

    // Optimize
    dragon_llvm_lifter_run_mem2reg(lifter);
    dragon_llvm_lifter_run_inst_combine(lifter);
    dragon_llvm_lifter_run_gvn(lifter);
    dragon_llvm_lifter_run_dce(lifter);

    // Optimized IR
    ir = dragon_llvm_lifter_ir(lifter);
    printf("%s", ir);
    dragon_cstr_free(ir);
}

dragon_function_destroy(fn);
dragon_llvm_lifter_destroy(lifter);
dragon_graph_destroy(graph);
```

**API summary**

| Function | Returns | Notes |
|---|---|---|
| `dragon_llvm_lifter_create(arch, module_name)` | `dragon_llvm_lifter_t*` | `module_name` may be NULL (defaults to `"lifted"`) |
| `dragon_llvm_lifter_destroy(l)` | — | |
| `dragon_llvm_lifter_lift(l, fn, graph)` | `int` (0/1) | 0 if any IGNIL block is missing |
| `dragon_llvm_lifter_ir(l)` | `char*` (heap) | Free with `dragon_cstr_free` |
| `dragon_llvm_lifter_run_mem2reg(l)` | — | Promotes allocas → SSA |
| `dragon_llvm_lifter_run_inst_combine(l)` | — | Folds sub-register patterns |
| `dragon_llvm_lifter_run_gvn(l)` | — | Eliminates redundant loads |
| `dragon_llvm_lifter_run_dce(l)` | — | Removes dead flag computations |
| `dragon_llvm_lifter_load_ir(l, text)` | `int` (0/1) | Import verified IR; failure preserves the module |
| `dragon_llvm_lifter_run_loop_reroll(l)` | `size_t` | Number of fixed-count loops created, zero on NULL/no match |
| `dragon_llvm_version()` | borrowed `const char*` | LLVM linked into this library; do not free |
| `dragon_llvm_lifter_run_pass_pipeline(l, pipeline, error)` | `int` (0/1) | In-process PassBuilder; verifies a clone before committing |
| `dragon_llvm_lifter_verify(l, error)` | `int` (0/1) | Structural LLVM verification, not semantic equivalence |

`run_pass_pipeline` accepts e.g. `"default<O2>"` or
`"function(instcombine,early-cse,dce)"`. Empty/invalid pipelines are errors;
parse/structural verification failure preserves the old module. The optional
`char **error` receives NULL on success or a heap diagnostic on failure; release
it using `dragon_cstr_free`. NULL lifters/pipelines return 0 with a diagnostic
when requested. No external `opt` executable is invoked. The pipeline is not a
resource sandbox and cannot replace independent equivalence/coverage checks.


The library also registers three function pipeline names:

- `function(dragon-coalesce-add-reductions)` quotients independent same-width
  wrapping ADD recurrences by their sum, only when every observation uses all
  selected accumulators once. Currently limited to two-block, single-latch
  loops. Per-lane observations, feedback and flagged updates are not guessed.
  PHI `!dragon.reduction` metadata proposes original coordinates; it is not a
  proof. Callers must independently verify seeds, parallel next state, guard
  and observations with the proposed many-to-one mapping.
- `function(dragon-fold-small-selects)` folds EQ/NE select DAGs over one
  i1..i4 selector into integer-valued finite-difference polynomials. Every
  selector value is enumerated; payload arithmetic retains its original modular
  width, and falling products are widened before integer division. Selector
  and opaque operands are frozen once. Only degree-at-most-4 results that
  strictly reduce instruction count are committed; unsupported DAGs stay intact.
- `function(dragon-normalize-modular-polynomials)` performs bounded exact
  integer-ring normalization, committing only smaller closed arithmetic cones.
  KnownBits may justify constant bitwise-to-arithmetic conversion and redundant
  ADD flags. Width-changing operations, select, memory and freeze remain
  opaque. Limits: 64 monomials, degree 4, depth 64 and 65,536 work units per
  function; exhaustion leaves the remaining expressions unchanged.

For recovered scalar loops, run InstCombine before coalescing packed PHIs,
then small-select folding, polynomial normalization and scalar cleanup. These transformations do not
perform loop discovery, recover omitted entry paths or establish native-code
coverage. LLVM verification alone does not establish semantic equivalence.

Reroll runs after O2 and uses exact closed scalar integer graph matching,
including flags and constants. It does not discover input-bound loops or rewrite
memory/calls. Search budget exhaustion leaves remaining code unchanged. Callers
must verify emitted IR and semantic equivalence separately.

---

## Symbolic execution

Declared inside `#ifdef DRAGON_WITH_Z3`, so this section is only available
when the library was built with `-DDRAGON_USE_Z3=ON`.

Runs lifted IGNIL over Z3 bitvectors. Four handle types, all owned by the
caller: `dragon_symexec_t` (the executor, its state and its solver),
`dragon_symexpr_t` (one Z3 expression), `dragon_symrun_t` (one run's outcome)
and `dragon_solution_t` (a satisfying assignment).

> A `dragon_symexpr_t` may safely outlive the `dragon_symexec_t` that
> produced it: a Z3 expression does not own its context, so each expression
> handle holds a reference to the executor and `dragon_symexec_destroy` only
> drops yours. Destroy every handle you are given, in whatever order suits
> the caller.

### Setting up and running

Registers are named by their IGNIL register-space byte offset and bit width —
the values in `x86IGNILRegs.hpp` / `armIGNILRegs.hpp` (`RAX` is offset 0
width 64, `EAX` offset 0 width 32, `AH` offset 1 width 8).

XMM registers use two 64-bit descriptors: XMM*i* low at `143 + 8*i`, and
XMM*i* high at `288 + 8*i` (0 <= i < 16). The low-half ABI and FS/GS offsets
remain unchanged. Read, symbolize or initialize both descriptors for a full
128-bit input; a low-half write alone does not initialize the high half. A raw
LLVM lifted-function register buffer covering the complete x86 namespace needs
416 bytes. This does not change the opaque symbolic-executor allocation API.


```c
// NULL options means all library defaults.
dragon_symexec_t* ex = dragon_symexec_create(NULL);

dragon_symexec_set_register(ex, /*RDI*/ 56, 64, 0x4000);
dragon_symexpr_t* flag = dragon_symexec_symbolize_memory(ex, 0x4000, 8, "flag");

dragon_symrun_t* run = dragon_symexec_run(ex, block);
printf("exit=%d complete=%d\n",
       dragon_symrun_exit(run), dragon_symrun_complete(run));
```

State persists across runs, so walking a path is a sequence of
`dragon_symexec_run` calls. `dragon_symexec_reset` clears it.

Options default when left at zero, so a zero-initialised struct means "all
defaults". The three flags are tri-state for that reason: `0` keeps the
default, `1` turns the behaviour on, `-1` turns it off.

```c
dragon_symexec_options_t opts = {0};
opts.max_branch_targets = 1024;
opts.stop_at_terminator = -1;      // trace mode: step over interior jumps
dragon_symexec_t* ex = dragon_symexec_create(&opts);
```

### Writing values back and reading them concretely

`dragon_symexec_set_register` / `dragon_symexec_map_memory` seed *host
integers* / *concrete blobs*. To write an *expression* into the machine
state — the output of a previous computation, say — use
`dragon_symexec_write_register` and `dragon_symexec_write_memory` (the memory
form stores little-endian, as many bytes as the expression is wide).

For the reverse — pulling a value back out when you expect it to be
concrete — `dragon_symexec_concrete_register` and
`dragon_symexec_concrete_memory` are the cheap form of read-then-evaluate: no
expression handle, no solver. Each returns 1 and writes `*out` when the value
is a literal of at most 64 bits, and 0 (leaving `*out` alone) when it is
symbolic or wider.

```c
uint64_t rax;
if (dragon_symexec_concrete_register(ex, /*RAX*/ 0, 64, &rax))
    printf("RAX = 0x%llx\n", (unsigned long long)rax);
```

### Fresh-variable tags and concrete opaques

When a run meets a load it cannot resolve it invents a fresh variable named
after the op's address and position, so running one block in two contexts
hands out the same names. `dragon_symexec_set_fresh_tag` appends a per-context
suffix that keeps them apart (NULL or `""` restores the untagged names).

`dragon_symexec_set_concrete_opaque` makes an `OPAQUE` op (`CPUID`=0,
`RDTSC`=1, `RDTSCP`=2) return fixed `results` instead of a symbol, so a
concolic trace stays concrete through an anti-tamper `CPUID`. `selector`
identifies the invocation from its operands — for `CPUID` it is
`(leaf << 32) | (subleaf & 0xffffffff)`, for `RDTSC`/`RDTSCP` it is 0 — and
`results` are the per-result-index values (for `CPUID`: `EAX`, `EBX`, `ECX`,
`EDX`). Only matching ops are overridden; everything else keeps the configured
default: host timestamps for RDTSC/RDTSCP, symbolic results for other kinds.

```c
uint64_t cpuid1[] = { 0x000306c3, 0, 0x7ffafbbf, 0xbfebfbff };
dragon_symexec_set_concrete_opaque(ex, /*CPUID*/ 0, /*leaf 1*/ 1ull << 32,
                                   cpuid1, 4);
```

### Native timestamp default

`dragon_symexec_create` enables native analysis-host RDTSC/RDTSCP by default.
Use `dragon_symexec_set_host_timestamps(ex, 0)` to keep timestamp results symbolic,
and `dragon_symexec_host_timestamps(ex)` to query the setting. No fields were
added to `dragon_symexec_options_t`; its existing layout is unchanged.

`dragon_symrun_host_timestamp_count(result)` and
`dragon_symrun_host_timestamp(result, index, &address, &kind, &tsc, &aux)` expose
one paired sample per dynamic instruction (`kind`: RDTSC=1, RDTSCP=2; AUX unused
for RDTSC). The indexed accessor returns 0 for null/out-of-range results and
accepts null output pointers. Explicit OPAQUE overrides take precedence.
Unsupported host instructions remain symbolic with a warning. These samples
are not source-machine timing replay; proofs using them are conditional on the
recorded measurements. Restoring a symbolic state does not replay host events.

### Snapshots and merging

Copying the machine state is far cheaper than rebuilding it, so an analysis
that runs many blocks from the same seeded start should seed once, snapshot,
and restore before each block rather than create a fresh executor every time.
`dragon_symexec_snapshot` returns an owned `dragon_symstate_t` (which keeps its
executor alive by itself, exactly as an expression handle does);
`dragon_symexec_restore` replaces the executor's state wholesale from a
snapshot taken on that same executor.

```c
dragon_symstate_t* base = dragon_symexec_snapshot(ex);
// ... run a block, inspect ...
dragon_symexec_restore(ex, base);   // back to the seeded start
dragon_symstate_destroy(base);
```

`dragon_symstate_merge` joins one snapshot into another: every register or
memory byte the two disagree on becomes, in the target, a fresh variable named
after a tag, and the call returns those symbolised locations as a diff list
(see below). An empty result means the incoming state added nothing — the
fixed-point test of a worklist exploration. Both snapshots must come from the
same executor.

`dragon_symstate_join_guarded(into, incoming, condition)` instead performs an
exact physical-state selection at a complete native-block boundary: incoming on
condition, into otherwise. It retains guarded values and constraint suffixes,
discards block-local temporaries, and returns an owned Boolean `dragon_symexpr_t`
projection-violation handle for an independent UNSAT check (`NULL` on failure).
Snapshots must share their executor/image backing; array memory effects and active
access observers are excluded. No coverage, disjointness or cross-call applicability
is established by this operation. Unlike widening merge, it adds no free tops.

### Diffing state

`dragon_symexec_diff` reports everything whose value differs from an earlier
snapshot, coalesced into the widest runs that came from one written value — the
batch form of reading every candidate location back and comparing. Each entry
is a register (`kind == 0`, `key` is an IGNIL register-space byte offset) or a
memory location (`kind == 1`, `key` is an address), with the run's `width` in
bits; `dragon_symdiff_value` hands back an owned expression handle for it.

```c
dragon_symstate_t* before = dragon_symexec_snapshot(ex);
dragon_symexec_run(ex, block);

dragon_symdiff_t* d = dragon_symexec_diff(ex, before);
for (size_t i = 0; i < dragon_symdiff_count(d); ++i) {
    int kind; uint64_t key; uint8_t width;
    dragon_symdiff_entry(d, i, &kind, &key, &width);
    dragon_symexpr_t* val = dragon_symdiff_value(d, i);
    char* s = dragon_symexpr_to_string(val);
    printf("%s %llu (%u bits) = %s\n", kind ? "mem" : "reg",
           (unsigned long long)key, width, s);
    dragon_cstr_free(s);
    dragon_symexpr_destroy(val);
}
dragon_symdiff_destroy(d);
dragon_symstate_destroy(before);
```

`dragon_symstate_merge` returns the same `dragon_symdiff_t` type; destroy it
with `dragon_symdiff_destroy` either way.

### Building expressions

There is no way to pass a Z3 expression across a C boundary, so the shim
provides leaf constructors and a binary-operator builder instead.

```c
dragon_symexpr_t* rax = dragon_symexec_read_register(ex, /*RAX*/ 0, 64);
dragon_symexpr_t* target = dragon_symexec_const(ex, 0xdeadbeef, 64);
dragon_symexpr_t* goal = dragon_symexpr_binop(DRAGON_SYMOP_EQ, rax, target);

char* text = dragon_symexpr_to_string(goal);
puts(text);
dragon_cstr_free(text);
```

`dragon_symexpr_binop` returns `NULL` rather than crashing when the operands'
sorts do not fit the operator — mismatched widths, a boolean where a bitvector
belongs, or two expressions from different executors.

Operators `DRAGON_SYMOP_ADD` … `DRAGON_SYMOP_XOR` take and return bitvectors;
`DRAGON_SYMOP_EQ` … `DRAGON_SYMOP_SGE` take bitvectors and return a boolean
(`ULT`/`ULE`/`UGT`/`UGE` unsigned, `SLT`/`SLE`/`SGT`/`SGE` signed);
`DRAGON_SYMOP_BOOL_AND`/`BOOL_OR`/`IMPLIES` take and return booleans.
`dragon_symexpr_not` is boolean negation.

Beyond `dragon_symexpr_to_string`, an expression can be inspected without the
solver: `dragon_symexpr_width` gives a bitvector's width in bits (0 for a
boolean), `dragon_symexpr_is_bool` distinguishes the two, and
`dragon_symexpr_as_u64` writes `*out` and returns 1 when the expression folds
to a literal of at most 64 bits (the cheap "is this already constant?" check,
no solver query). `dragon_symexpr_to_smt2` renders a complete, self-contained
SMT-LIB 2 script — declarations included — that another Z3 binding can parse
back without being told what the free variables are; free it with
`dragon_cstr_free`.

```c
uint64_t v;
if (dragon_symexpr_as_u64(rax, &v))
    printf("already concrete: 0x%llx\n", (unsigned long long)v);
```

### Solver queries

The tri-state predicates return `1` (yes), `0` (no) or `-1` (the solver timed
out or gave up) — never a guess.

```c
dragon_symexec_assume(ex, precondition);

int holds = dragon_symexec_proves(ex, goal);

uint64_t value;
if (dragon_symexec_evaluate(ex, rax, &value))
    printf("forced to a single value: 0x%llx\n", (unsigned long long)value);

uint64_t targets[64];
int exhaustive = 0;
size_t n = dragon_symexec_enumerate(ex, rax, targets, 64, &exhaustive);
```

`dragon_symexec_evaluate` writes `*out` only when the path constraints force
exactly one value — the "is this obfuscated expression really a constant?"
query. `dragon_symexec_enumerate` sets `*out_exhaustive` to 1 only when the
enumeration ran out of values rather than hitting `max`.

### Reading a model

A symbolic region of N bytes creates N variables named `<region>[0]`..
`<region>[N-1]`; `dragon_solution_bytes` reads them back in address order. It
returns the region's full size and writes at most `cap` bytes, so calling it
with `cap == 0` gives the size to allocate.

```c
dragon_solution_t* sol = dragon_symexec_solve(ex, goal);
if (sol) {
    size_t   size  = dragon_solution_bytes(sol, "flag", NULL, 0);
    uint8_t* bytes = malloc(size);
    dragon_solution_bytes(sol, "flag", bytes, size);

    uint64_t n;
    if (dragon_solution_value(sol, "some_symbol", &n))
        printf("some_symbol = %llu\n", (unsigned long long)n);

    free(bytes);
    dragon_solution_destroy(sol);
}
```

`dragon_symexec_solve` returns `NULL` when no assignment exists — an
unreachable goal is reported, never guessed at. Pass `NULL` for `goal` to
solve the path constraints alone. `dragon_solution_each` walks every bound
symbol.

### Reading a run's control flow

```c
for (size_t i = 0; i < dragon_symrun_successor_count(run); ++i) {
    uint64_t addr; int taken;
    dragon_symrun_successor(run, i, &addr, &taken);
    printf("  -> 0x%llx (taken=%d)\n", (unsigned long long)addr, taken);

    // The guard under which that successor is reached; owned.
    dragon_symexpr_t* guard = dragon_symrun_successor_condition(run, i);
    dragon_symexpr_destroy(guard);
}

for (size_t i = 0; i < dragon_symrun_warning_count(run); ++i) {
    uint64_t at;
    char* msg = dragon_symrun_warning(run, i, &at);
    printf("  warning @0x%llx: %s\n", (unsigned long long)at, msg);
    dragon_cstr_free(msg);
}
```

`dragon_symrun_complete` is the honesty check: `1` only when the run succeeded
*and* every address and branch target resolved exactly, so the successor list
really is the complete set of reachable addresses. Otherwise the warnings say
what had to be left open.

`dragon_symrun_stats` reports how much work the run did — ops executed, solver
queries issued, and addresses concretized — through three `size_t` out-params,
any of which may be NULL.

`dragon_symrun_status` returns a `dragon_symexec_status_t`
(`DRAGON_SYMEXEC_OK`, `_MALFORMED_OP`, `_UNSUPPORTED_OP`, `_SOLVER_FAILURE`)
and `dragon_symrun_exit` a `dragon_symexec_exit_t` describing how the block
left off (`DRAGON_SYMEXIT_FALLTHROUGH`, `_JUMP`, `_CONDITIONAL_JUMP`, `_CALL`,
`_RETURN`, `_ERROR`). `dragon_symrun_error` returns NULL on success, otherwise
a heap string to free with `dragon_cstr_free`.

### Unresolved accesses

When a `LOAD` or `STORE` has an address with too many satisfying values to
expand, the run leaves it open: the `LOAD` produces a fresh variable and the
`STORE` is dropped, each with a warning. A caller rebuilding code from the run
needs the access itself, which `dragon_symrun_unresolved_*` provides. Each
entry reports whether it is a store, the machine address of the op, and the
access width, plus owned expression handles for the address and for the value
stored (or the variable standing in for the value loaded).

```c
for (size_t i = 0; i < dragon_symrun_unresolved_count(run); ++i) {
    int is_store; uint64_t op_addr; uint8_t width;
    dragon_symrun_unresolved(run, i, &is_store, &op_addr, &width);

    dragon_symexpr_t* addr = dragon_symrun_unresolved_address(run, i);
    dragon_symexpr_t* val  = dragon_symrun_unresolved_value(run, i);
    char* as = dragon_symexpr_to_string(addr);
    char* vs = dragon_symexpr_to_string(val);
    printf("%s @0x%llx (%u bits): [%s] %s %s\n",
           is_store ? "store" : "load", (unsigned long long)op_addr, width,
           as, is_store ? "<-" : "->", vs);
    dragon_cstr_free(as); dragon_cstr_free(vs);
    dragon_symexpr_destroy(addr);
    dragon_symexpr_destroy(val);
}
```

### API summary

| Function | Description |
|---|---|
| `dragon_symexec_create(opts)` / `_destroy` / `_reset` | Executor lifetime |
| `dragon_symexec_set_register(e, off, width, value)` | Seed a register concretely |
| `dragon_symexec_symbolize_register(e, off, width, name)` | Bind it to a fresh variable |
| `dragon_symexec_map_memory(e, addr, data, len)` | Map a concrete blob |
| `dragon_symexec_symbolize_memory(e, addr, size, name)` | Per-byte variables for a region |
| `dragon_symexec_write_register/write_memory(e, …, x)` | Write an expression into the state |
| `dragon_symexec_concrete_register/concrete_memory(e, …, out)` | Cheap literal read (1 if concrete) |
| `dragon_symexec_assume(e, cond)` | Constrain the rest of the run |
| `dragon_symexec_set_fresh_tag(e, tag)` | Suffix for unresolved-load variable names |
| `dragon_symexec_set_concrete_opaque(e, kind, selector, results, n)` | Fixed result for a `CPUID`/`RDTSC` op |
| `dragon_symexec_snapshot(e)` / `dragon_symexec_restore(e, s)` | Save/restore machine state |
| `dragon_symstate_merge(into, incoming, tag)` / `dragon_symstate_destroy` | Join states; destroy a snapshot |
| `dragon_symexec_diff(e, before)` | Locations changed since a snapshot |
| `dragon_symdiff_count/entry/value/destroy` | Read a diff list |
| `dragon_symexec_const/read_register/read_memory` | Leaf expressions |
| `dragon_symexpr_binop(op, a, b)` / `_not(a)` | Build expressions; NULL on a sort mismatch |
| `dragon_symexpr_to_string/to_smt2/width/is_bool/as_u64/destroy` | Inspect and free an expression |
| `dragon_symexec_run(e, block)` | Execute a block; state persists |
| `dragon_symrun_status/exit/complete/error/stats` | What the run did |
| `dragon_symrun_successor_count/successor/successor_condition` | Reachable addresses |
| `dragon_symrun_unresolved_count/unresolved/unresolved_address/unresolved_value` | Loads/stores left open |
| `dragon_symrun_warning_count/warning` / `dragon_symrun_destroy` | Warnings; free the run |
| `dragon_symexec_proves/is_satisfiable` | Tri-state: 1 yes, 0 no, -1 unknown |
| `dragon_symexec_evaluate(e, x, out)` | Value, only if forced to exactly one |
| `dragon_symexec_enumerate(e, x, out, max, exhaustive)` | Distinct satisfying values |
| `dragon_symexec_solve(e, goal)` | A satisfying assignment, or NULL |
| `dragon_solution_value/bytes/each/destroy` | Read the model back |

---

## FLIRT signatures

`dragon_sigdb_t` wraps a `SignatureDB` — a loaded collection of FLIRT-style
`.pat` signatures. Destroy it with `dragon_sigdb_destroy` when no longer
needed.

Text `.pat` format only (the proprietary binary `.sig` format is not
supported). The CRC16 variant used (`dragon_sigs_crc16`) is a standard one
(reflected, poly `0xA001`, init `0xFFFF`, no final XOR — CRC-16/ARC) but was
never verified against a real IDA/FLAIR-generated `.pat` file — if you load
a real signature database and nothing ever matches, check this first.

```c
dragon_sigdb_t* db = dragon_sigdb_create();
dragon_sigdb_load_directory(db, "./signatures");   // every .pat file in the dir
printf("loaded %zu signatures\n", dragon_sigdb_signature_count(db));

// Single candidate: try every signature against bytes starting at `address`.
uint64_t match_addr; char* match_name; uint32_t match_len;
if (dragon_sigdb_match_at(db, code, sizeof(code), 0x1000,
                          &match_addr, &match_name, &match_len)) {
    printf("matched: %s (len %u)\n", match_name, match_len);
    dragon_cstr_free(match_name);
}

// Many candidates at once: every entry point against every signature.
// A module can bundle more than one function/offset under one pattern, so
// one entry point may produce more than one callback invocation.
void on_match(uint64_t addr, const char* name, uint32_t len, void* user) {
    printf("0x%llx: %s (len %u)\n", (unsigned long long)addr, name, len);
}
uint64_t entry_points[] = { 0x1000, 0x1040 };
dragon_sigdb_match_entries(db, image, image_len, image_base,
                           entry_points, 2, on_match, NULL);

dragon_sigdb_destroy(db);
```

**API summary**

| Function | Returns | Notes |
|---|---|---|
| `dragon_sigdb_create()` | `dragon_sigdb_t*` | |
| `dragon_sigdb_destroy(db)` | — | |
| `dragon_sigdb_load_directory(db, dir)` | — | Every `.pat` file directly inside `dir`, not recursive; unparseable files are silently skipped |
| `dragon_sigdb_load_file(db, path)` | — | No-op if the file can't be parsed |
| `dragon_sigdb_signature_count(db)` | `size_t` | |
| `dragon_sigs_crc16(data, len)` | `uint16_t` | The raw CRC16 primitive, exposed standalone for verifying it against real `.pat` data |
| `dragon_sigdb_match_at(db, bytes, len, address, &out_address, &out_name, &out_length)` | `int` (0/1) | `out_name` is heap-allocated — free with `dragon_cstr_free`; any out-pointer may be NULL |
| `dragon_sigdb_match_entries(db, image, image_len, image_base, entry_points, n, cb, user)` | — | Callback receives `(address, name, length, user)`; `name` is borrowed, valid only during the callback |

### Resolved-path LLVM export

`dragon_llvm_lifter_lift_path(l, steps, count, name)` accepts an array of
`dragon_llvm_path_step_t`: borrowed `body` (nullable), `address`, `next_address`,
`transfer` (0=next, 1=call, 2=return), `return_address`, `stack_adjustment`.
Returns zero for null/empty/invalid paths. This is additive; existing API structs
are unchanged. Currently x86-64 only. The final step must return, adjacent
addresses must agree and a body's own CALL/RET is invalid. The function models
transfer stack effects and emits target guards with `llvm.assume`. Existing LLVM
optimization and `dragon_llvm_lifter_ir` work unchanged. Results remain finite
path-specialized `(mem, regs)` functions, not all-path or standalone replay.

### Typed expressions and ordered memory effects (Z3 build)

- `dragon_llvm_lifter_lift_expression(l, expression, arguments, count, name)`:
  actual pure Bool/BV return DAG -> typed LLVM function; reject undeclared or
  unsupported dependencies, mixed contexts and duplicate inputs.
- `dragon_symexec_enable_memory_effects(e)`: opt in **before** path execution.
  Every IGNIL LOAD/STORE uses one initially unconstrained BV64-to-BV8 array,
  rather than specializing runtime buffer values from captured/concrete memory.
- `dragon_symexec_memory_effect_count(e)` / `dragon_symexec_memory_effect(e, i,
  &is_store, &pc, &width)`: inspect ordered events. Address/value getters return
  owned `dragon_symexpr_t*`; a load's value is its fresh runtime result token.
- `dragon_symexec_effect_memory(e, initial)` returns the current/initial array;
  `dragon_symexec_effect_constraints(e)` returns the conjunction tying load
  tokens to their array versions. SMT-LIB serialization supports array sorts.
- `dragon_llvm_lifter_lift_effects(l, e, expression, arguments,
  pointer_arguments, count, name)`: real ordered loads/stores plus return;
  `expression=NULL` means void. Each nonzero pointer flag requires a BV64 symbol
  and exports it as `ptr`, without noalias/inbounds assumptions. Alignment is 1.
  Invalid histories/dependencies return zero without a partial LLVM function.

All expression handles retain their context. State snapshots include arrays and
ordered histories; reset disables the mode, widening merge/concrete diff return
NULL for effect states. Unlifted blocks and failed/warned runs invalidate effect
export. Callers still validate source coverage, ABI and finite-path preconditions.
This is ordinary valid x86-64 memory semantics, not volatile/MMIO, atomic,
concurrency, fault or all-path/native-equivalence certification. It does not
convert an already capture-specialized run to a pointer-generic function.

### Physical-state analysis / symbolic loop regions

- `dragon_symexec_begin_access_trace(e, ranges, count)` starts an opt-in byte
  observer. `dragon_state_range_t` contains `kind` (0 register / 1 memory),
  `key` (byte offset/address), and `bytes`; an empty array watches all accesses.
  The C boundary rejects individual watched ranges exceeding 4096 bytes.
- `dragon_symexec_end_access_trace(e, callback, user)` disables the shared
  observer and reports `(kind, key, flags, user)` once per byte. Flags are
  live-before-first-write=1, read=2, written=4. Return 0 means tracking overflow;
  callers must fail closed, not use an incomplete footprint. Distinct-byte
  capacity is 1,048,576. Snapshots share the observer until it is disabled.
- `dragon_symexec_symbolize_range(e, kind, key, width, name)` binds a physical
  range without architectural GPR zero-extension. Real instruction writes are
  unchanged. The returned owned `dragon_symexpr_t` keeps the executor alive.
- `dragon_symexec_parse_condition(e, script)` parses the conjunction of SMT-LIB
  assertions into the same context, without adding assumptions. NULL means
  invalid input. Names **and sorts** must match the intended existing symbols.
- `dragon_symexec_specialize_equality(e, equality)` proves the equality before
  rewriting physical state. Returns 1 rewritten, 0 not implied, -1
  invalid/unknown. Assumptions remain intact. Excludes memory-effects mode.
- Passing an empty result array to `dragon_symexec_set_concrete_opaque` removes
  the matching override and restores the configured default behavior.
- `dragon_llvm_lifter_lift_loop_region(l, inputs, input_count, carried,
  next_values, carried_count, continuation, name)` builds simultaneous loop PHIs
  and returns a struct of state at the header where continuation fails. This
  does not manufacture the original entry/exit projection or prove invariants,
  termination, or all-path native equivalence. See `dragon_c.h` for ownership
  and the exact signature; scalar expression handles follow the usual rules.

### Deterministic full physical-state summaries

- `dragon_symexec_begin_call_trace(e)` creates an owned collector. Capture entry
  state first. Snapshots share a union footprint but copy definite-write sets.
  `dragon_symexec_detach_call_trace(e, trace)` records each matched return's
  definite writes and detaches only that restored path. `dragon_call_trace_cacheable`
  checks eligibility, not all-path coverage; destroy with `dragon_call_trace_destroy`.
- `dragon_state_summary_build(before, after, trace, return_slot, tag, from, to,
  count, &error)` consumes the completed footprint after independently established
  coverage and exact full-state return joining. `from/to` must be exact established
  equations. NULL indicates rejection; free the optional owned error string with
  `dragon_cstr_free`. States, trace and rewrite expressions must share an executor.
- `dragon_state_summary_projection(s)` and
  `dragon_state_summary_applicability(s, e)` return owned Boolean expression
  handles. Independently prove each UNSAT (projection once; applicability for every
  current state) before `dragon_state_summary_apply(s, e)`. Apply returns 1 on
  success, 0 on incompatibility; it does not perform those proofs itself. Input
  correlations are covered existentially, not assumed away. No state mutation
  may intervene between applicability proof and application.
- `dragon_state_summary_input_count` / `dragon_state_summary_output_count` report
  range counts. `dragon_state_summary_destroy` releases the owned summary. All
  owned handles keep the underlying executor/context alive.
- Inputs are path-local read-before-write and conditionally preserved bytes;
  outputs are all written bytes, including writes equal to the old source value.
  Parallel input evaluation and raw-range writes preserve physical overlaps.
- `dragon_symexec_read_control_memory(e, addr, width)` marks only actual RET target
  reads. Data reads use the ordinary API. The invocation's own return-slot control
  input can vary; data uses still match, and writes to that slot reject caching.
  The caller supplies the new actual control successor.
- Ordinary shared-image fixed-layout states only; no stack/address rebasing,
  array effects or active loop observer. OPAQUE/UNDEF, unsupported/unlifted or
  unresolved execution and widening invalidate candidates. Host timestamps are
  never silently frozen into reusable summaries. Coverage, return-stack matching
  and scalar-LLVM projection proofs are separate caller responsibilities.
