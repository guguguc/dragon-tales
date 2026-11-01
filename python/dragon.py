import os
import re
import cffi

# -- cffi setup ----------------------------------------------------------------

_here = os.path.dirname(os.path.abspath(__file__))
_root = os.path.dirname(_here)

_HEADER = os.path.join(_root, 'c_shim', 'dragon_c.h')
import sys as _sys

def _find_lib():
    env = os.environ.get('DRAGON_C_LIB')
    if env and os.path.exists(env):
        return env
    if os.name == 'nt':
        names = ['dragon_c.dll']
    elif _sys.platform == 'darwin':
        names = ['libdragon_c.dylib', 'libdragon_c.so']
    else:
        names = ['libdragon_c.so']
    dirs = [
        os.path.join(_root, 'build', 'c_shim'),
        os.path.join(_root, 'build', 'bin', 'Release'),
        os.path.join(_root, 'build', 'bin', 'Debug'),
        os.path.join(_root, 'build', 'c_shim', 'Release'),
        os.path.join(_root, 'build', 'c_shim', 'Debug'),
    ]
    for d in dirs:
        for n in names:
            cand = os.path.join(d, n)
            if os.path.exists(cand):
                return cand
    return os.path.join(_root, 'build', 'c_shim', 'libdragon_c.so')

_LIB = _find_lib()
if os.name == 'nt':
    # so the shim's dependency DLLs (dragon.dll, libz3.dll) resolve
    try:
        os.add_dll_directory(os.path.dirname(_LIB))
    except (AttributeError, OSError):
        pass

ffi = cffi.FFI()


def _prepare_cdef(path):
    with open(path) as f:
        src = f.read()
    # Remove #ifdef __cplusplus ... #endif blocks (includes extern "C" { })
    src = re.sub(r'#ifdef\s+__cplusplus.*?#endif', '', src, flags=re.DOTALL)
    # Remove remaining preprocessor lines (#pragma, #include, etc.)
    src = re.sub(r'^\s*#.*$', '', src, flags=re.MULTILINE)
    return src


ffi.cdef(_prepare_cdef(_HEADER))
lib = ffi.dlopen(_LIB)


# -- enums ---------------------------------------------------------------------

class Architecture:
    """
    Possible Architectures supported by dragon
    these are supported for assembly and disassembly.
    """
    UNKNOWN = 0
    X86_32 = 1
    X86_64 = 2
    ARM32 = 3
    ARM64 = 4
    RISCV32 = 5
    RISCV64 = 6


class Syntax:
    """
    Syntax used in configuration to show the disassembled code
    they can be INTEL or ATT.
    """
    INTEL = 0
    ATT = 1


class Strategy:
    """
    Strategies to use in the disassembler, for the moment only
    linear sweep and recursive traversal are available. Others
    like a hybrid approach will be implemented.
    """
    LINEAR_SWEEP = 0
    RECURSIVE_TRAVERSAL = 1


# -- Instruction ---------------------------------------------------------------

class Instruction:
    """Lightweight view into the graph listing — not owned, no destroy."""

    def __init__(self, ptr):
        self._ptr = ptr

    @property
    def address(self):
        return lib.dragon_instruction_address(self._ptr)

    @property
    def size(self):
        return lib.dragon_instruction_size(self._ptr)

    @property
    def mnemonic(self):
        return ffi.string(lib.dragon_instruction_mnemonic(self._ptr)).decode()

    @property
    def operands(self):
        return ffi.string(lib.dragon_instruction_operands(self._ptr)).decode()

    @property
    def disassembly(self):
        return ffi.string(lib.dragon_instruction_disassembly(self._ptr)).decode()

    @property
    def pattern(self):
        return ffi.string(lib.dragon_instruction_pattern(self._ptr)).decode()

    @property
    def bytes(self):
        length = ffi.new('size_t *')
        ptr = lib.dragon_instruction_bytes(self._ptr, length)
        return bytes(ffi.buffer(ptr, length[0]))

    @property
    def chromosome_mask(self):
        length = ffi.new('size_t *')
        ptr = lib.dragon_instruction_chromosome_mask(self._ptr, length)
        return bytes(ffi.buffer(ptr, length[0]))

    @property
    def is_block_start(self):    return bool(lib.dragon_instruction_is_block_start(self._ptr))

    @property
    def is_function_start(self): return bool(lib.dragon_instruction_is_function_start(self._ptr))

    @property
    def is_prologue(self):       return bool(lib.dragon_instruction_is_prologue(self._ptr))

    @property
    def is_return(self):         return bool(lib.dragon_instruction_is_return(self._ptr))

    @property
    def is_call(self):           return bool(lib.dragon_instruction_is_call(self._ptr))

    @property
    def is_jump(self):           return bool(lib.dragon_instruction_is_jump(self._ptr))

    @property
    def is_conditional(self):    return bool(lib.dragon_instruction_is_conditional(self._ptr))

    @property
    def is_trap(self):           return bool(lib.dragon_instruction_is_trap(self._ptr))

    @property
    def has_indirect_target(self): return bool(lib.dragon_instruction_has_indirect_target(self._ptr))

    @property
    def edges(self):             return lib.dragon_instruction_edges(self._ptr)

    @property
    def branches(self):
        result = []
        cb = ffi.callback('void(uint64_t, void *)', lambda addr, _: result.append(addr))
        lib.dragon_instruction_each_branch(self._ptr, cb, ffi.NULL)
        return result

    @property
    def callees(self):
        result = []
        cb = ffi.callback('void(uint64_t, void *)', lambda addr, _: result.append(addr))
        lib.dragon_instruction_each_callee(self._ptr, cb, ffi.NULL)
        return result

    def __repr__(self):
        return f'<Instruction 0x{self.address:x}: {self.disassembly}>'


# -- BasicBlock ----------------------------------------------------------------

class BasicBlock:
    """Heap-allocated view - owns its pointer, must be destroyed."""

    def __init__(self, ptr):
        self._ptr = ptr

    def __del__(self):
        if self._ptr:
            lib.dragon_block_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    @property
    def is_valid(self):           return bool(lib.dragon_block_valid(self._ptr))

    @property
    def start_address(self):      return lib.dragon_block_start_address(self._ptr)

    @property
    def terminator_address(self): return lib.dragon_block_terminator_address(self._ptr)

    @property
    def size(self):               return lib.dragon_block_size(self._ptr)

    @property
    def byte_size(self):          return lib.dragon_block_byte_size(self._ptr)

    def instructions(self):
        result = []
        cb = ffi.callback('void(const dragon_instruction_t *, void *)',
                          lambda ptr, _: result.append(Instruction(ptr)))
        lib.dragon_block_each_instruction(self._ptr, cb, ffi.NULL)
        return result

    def successors(self):
        result = []
        cb = ffi.callback('void(uint64_t, void *)', lambda addr, _: result.append(addr))
        lib.dragon_block_each_successor(self._ptr, cb, ffi.NULL)
        return result

    def __repr__(self):
        return f'<BasicBlock 0x{self.start_address:x} valid={self.is_valid}>'


# -- Function ------------------------------------------------------------------

class Function:
    """Heap-allocated view - owns its pointer, must be destroyed."""

    def __init__(self, ptr):
        self._ptr = ptr

    def __del__(self):
        if self._ptr:
            lib.dragon_function_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    @property
    def is_valid(self):              return bool(lib.dragon_function_valid(self._ptr))

    @property
    def start_address(self):         return lib.dragon_function_start_address(self._ptr)

    @property
    def num_blocks(self):            return lib.dragon_function_num_blocks(self._ptr)

    @property
    def num_instructions(self):      return lib.dragon_function_num_instructions(self._ptr)

    @property
    def edges(self):                 return lib.dragon_function_edges(self._ptr)

    @property
    def byte_size(self):             return lib.dragon_function_byte_size(self._ptr)

    @property
    def cyclomatic_complexity(self): return lib.dragon_function_cyclomatic_complexity(self._ptr)

    def block_addresses(self):
        """Return start addresses of all blocks in this function."""
        result = []
        cb = ffi.callback('void(const dragon_block_t *, void *)',
                          lambda ptr, _: result.append(
                              lib.dragon_block_start_address(ptr)))
        lib.dragon_function_each_block(self._ptr, cb, ffi.NULL)
        return result

    def __repr__(self):
        return f'<Function 0x{self.start_address:x} valid={self.is_valid}>'


# -- Graph ---------------------------------------------------------------------

class Graph:
    """Owns the instruction listing and address queues."""

    def __init__(self, ptr):
        self._ptr = ptr

    def __del__(self):
        if self._ptr:
            lib.dragon_graph_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    def __len__(self):
        return lib.dragon_graph_size(self._ptr)

    def __bool__(self):
        return not lib.dragon_graph_empty(self._ptr)

    def get_instruction(self, address):
        ptr = lib.dragon_graph_get_instruction(self._ptr, address)
        if ptr == ffi.NULL:
            return None
        return Instruction(ptr)

    def get_block(self, address):
        return BasicBlock(lib.dragon_graph_get_block(self._ptr, address))

    def get_function(self, address):
        return Function(lib.dragon_graph_get_function(self._ptr, address))

    def instructions(self):
        result = []
        cb = ffi.callback('void(const dragon_instruction_t *, void *)',
                          lambda ptr, _: result.append(Instruction(ptr)))
        lib.dragon_graph_each_instruction(self._ptr, cb, ffi.NULL)
        return result

    def block_addresses(self):
        result = []
        cb = ffi.callback('void(uint64_t, void *)', lambda addr, _: result.append(addr))
        lib.dragon_graph_each_block_address(self._ptr, cb, ffi.NULL)
        return result

    def function_addresses(self):
        result = []
        cb = ffi.callback('void(uint64_t, void *)', lambda addr, _: result.append(addr))
        lib.dragon_graph_each_function_address(self._ptr, cb, ffi.NULL)
        return result

    def get_ignil_block(self, address):
        """Return the IGNILBlock for *address*, or None if not lifted yet."""
        ptr = lib.dragon_graph_get_ignil_block(self._ptr, address)
        if ptr == ffi.NULL:
            return None
        return IGNILBlock(ptr)

    def __repr__(self):
        return f'<Graph instructions={len(self)}>'


# -- Configuration -------------------------------------------------------------

class Configuration:
    """Holds syntax, disassembly strategy, and LLVM target knobs.

    Parameters
    ----------
    syntax : Syntax
        Assembly syntax used for printing (INTEL or ATT).
    strategy : Strategy
        Disassembly algorithm (LINEAR_SWEEP or RECURSIVE_TRAVERSAL).
    cpu : str
        LLVM CPU name forwarded to MCSubtargetInfo. An empty string selects
        the "generic" baseline for the target triple, which may omit optional
        ISA extensions. Examples:
            "cortex-a8"   -- ARMv7-A with Thumb2 and NEON
            "arm926ej-s"  -- ARMv5TEJ, enables BX/BLX on ARM32
            "skylake"     -- x86-64 with AVX2, BMI2, etc.
            "sifive-u74"  -- RISC-V 64 with M/A/C extensions
    features : str
        LLVM feature string forwarded to MCSubtargetInfo. Comma-separated
        list of features, each prefixed with '+' (enable) or '-' (disable).
        Combined with those implied by `cpu`. Examples:
            "+v4t"        -- enable ARMv4T on ARM32 (adds BX instruction)
            "+v7,+neon"   -- ARMv7 with NEON
            "+avx2"       -- enable AVX2 on x86
            "+m,+a,+c"    -- RISC-V multiply, atomics, compressed
    """

    def __init__(self, syntax=Syntax.INTEL, strategy=Strategy.LINEAR_SWEEP,
                 cpu='', features='', logging=False):
        self._ptr = lib.dragon_config_create(syntax, strategy)
        if self._ptr == ffi.NULL:
            raise RuntimeError('failed to create configuration')
        if cpu:
            lib.dragon_config_set_cpu(self._ptr, cpu.encode())
        if features:
            lib.dragon_config_set_features(self._ptr, features.encode())
        if logging:
            lib.dragon_config_set_logging(self._ptr, 1)

    def __del__(self):
        if self._ptr:
            lib.dragon_config_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    @property
    def syntax(self):
        return lib.dragon_config_syntax(self._ptr)

    @property
    def strategy(self):
        return lib.dragon_config_strategy(self._ptr)

    @property
    def cpu(self):
        """LLVM CPU name currently set (empty string means 'generic')."""
        return ffi.string(lib.dragon_config_cpu(self._ptr)).decode()

    @cpu.setter
    def cpu(self, value):
        lib.dragon_config_set_cpu(self._ptr, value.encode())

    @property
    def features(self):
        """LLVM feature string currently set."""
        return ffi.string(lib.dragon_config_features(self._ptr)).decode()

    @features.setter
    def features(self, value):
        lib.dragon_config_set_features(self._ptr, value.encode())

    @property
    def logging(self):
        """Whether diagnostic logging to stderr is enabled."""
        return bool(lib.dragon_config_logging(self._ptr))

    @logging.setter
    def logging(self, value):
        lib.dragon_config_set_logging(self._ptr, 1 if value else 0)

    def __repr__(self):
        cpu_part = f' cpu={self.cpu!r}' if self.cpu else ''
        feat_part = f' features={self.features!r}' if self.features else ''
        log_part = ' logging=True' if self.logging else ''
        return f'<Configuration syntax={self.syntax} strategy={self.strategy}{cpu_part}{feat_part}{log_part}>'


# -- Disassembler --------------------------------------------------------------

class Disassembler:
    """Disassembles raw bytes into a Graph given an architecture and configuration."""

    def __init__(self, arch=Architecture.X86_64, config=None):
        if config is None:
            config = Configuration()
        self._config = config
        self._ptr = lib.dragon_disasm_create(arch, config._ptr)
        if self._ptr == ffi.NULL:
            raise RuntimeError('failed to create disassembler')

    def __del__(self):
        if self._ptr:
            lib.dragon_disasm_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    @property
    def is_valid(self):
        return bool(lib.dragon_disasm_valid(self._ptr))

    def disassemble(self, bytes_data, base_address=0x0):
        """Disassemble raw bytes and return a Graph. Raises RuntimeError on failure."""
        buf = ffi.from_buffer(bytes_data)
        ptr = lib.dragon_disasm_disassemble(self._ptr, buf, len(bytes_data), base_address)
        if ptr == ffi.NULL:
            raise RuntimeError('disassembly failed — unsupported architecture or invalid input')
        return Graph(ptr)

    def analyze(self, bytes_data, base_address=0x0):
        """Disassemble and run architecture-specific analysis (block and function
        discovery). Returns a fully populated Graph. Raises RuntimeError on failure."""
        buf = ffi.from_buffer(bytes_data)
        ptr = lib.dragon_disasm_analyze(self._ptr, buf, len(bytes_data), base_address)
        if ptr == ffi.NULL:
            raise RuntimeError('analysis failed — unsupported architecture or invalid input')
        return Graph(ptr)

    def lift_trace(self, instructions):
        """Lift an arbitrary linear sequence of already-decoded instructions
        straight to IGNIL, bypassing CFG/function/block validity analysis —
        e.g. a captured execution trace (Unicorn/QBDI/Frida/Intel PT) that
        isn't claimed to form a single valid basic block or a coherent CFG.

        Parameters
        ----------
        instructions : list[Instruction]
            Consulted in the order given — they do not need to be contiguous
            or even from the same Graph, as long as they were decoded for
            this Disassembler's architecture. Typically the result of
            Graph.instructions() or repeated Graph.get_instruction() calls.

        Returns
        -------
        IGNILBlock
            An owned block (unlike Graph.get_ignil_block()'s borrowed one) —
            use as a context manager or let garbage collection destroy it.
            Empty for RISC-V (no IGNIL lifter yet) or an empty trace.
        """
        ptrs = ffi.new('const dragon_instruction_t *[]',
                       [insn._ptr for insn in instructions]) if instructions else ffi.NULL
        ptr = lib.dragon_disasm_lift_trace(self._ptr, ptrs, len(instructions))
        if ptr == ffi.NULL:
            raise RuntimeError('lift_trace failed')
        return IGNILBlock(ptr, owned=True)

    def __repr__(self):
        return f'<Disassembler valid={self.is_valid}>'


# -- Assembler -----------------------------------------------------------------

class Assembler:
    """Assembles source text to raw bytes."""

    def __init__(self, arch=Architecture.X86_64, config=None):
        if config is None:
            config = Configuration()
        self._config = config
        self._ptr = lib.dragon_asm_create(arch, config._ptr)
        if self._ptr == ffi.NULL:
            raise RuntimeError('failed to create assembler')

    def __del__(self):
        if self._ptr:
            lib.dragon_asm_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    @property
    def is_valid(self):
        return bool(lib.dragon_asm_valid(self._ptr))

    def assemble(self, source):
        """Assemble source text and return bytes. Raises RuntimeError on failure."""
        out_len = ffi.new('size_t *')
        ptr = lib.dragon_asm_assemble(self._ptr, source.encode(), out_len)
        if ptr == ffi.NULL:
            raise RuntimeError('assembly failed')
        try:
            return bytes(ffi.buffer(ptr, out_len[0]))
        finally:
            lib.dragon_bytes_free(ptr)

    def __repr__(self):
        return f'<Assembler valid={self.is_valid}>'


# -- IGNIL opcode names --------------------------------------------------------

class IGNILOpcode:
    """Mirror of dragon_ignil_opcode_t.  All values match the C enum."""
    COPY  = 0;  LOAD  = 1;  STORE = 2
    ADD   = 3;  SUB   = 4;  NEG   = 5;  MUL   = 6
    SDIV  = 7;  UDIV  = 8;  SMOD  = 9;  UMOD  = 10
    AND   = 11; OR    = 12; XOR   = 13; NOT   = 14
    SHL   = 15; SHR   = 16; SAR   = 17
    ZEXT  = 18; SEXT  = 19; TRUNC = 20
    EQ    = 21; NEQ   = 22
    ULT   = 23; ULE   = 24; UGT   = 25; UGE   = 26
    SLT   = 27; SLE   = 28; SGT   = 29; SGE   = 30
    JMP   = 31; CJMP  = 32; CALL  = 33; RET   = 34
    UNDEF = 35
    # Appended after UNDEF, not interleaved with ADD/SUB/MUL above where
    # they'd read more naturally - matches dragon_c.h's dragon_ignil_opcode_t.
    FADD = 36; FSUB = 37; FMUL = 38; FDIV = 39
    SITOFP = 40; FPTOSI = 41
    # An instruction whose result IGNIL cannot express but which is still a
    # determinate value (CPUID, RDTSC): see Op::aux for the kind and which
    # of the instruction's results the op defines.
    OPAQUE = 42

    @staticmethod
    def name(opcode_int):
        """Return the mnemonic string for an opcode integer."""
        return ffi.string(lib.dragon_ignil_opcode_name(opcode_int)).decode()


# -- IGNIL block ---------------------------------------------------------------

class IGNILBlock:
    """View of an IGNIL block.

    Blocks obtained from Graph.get_ignil_block() are borrowed — valid while
    the owning Graph is alive, and must not be destroyed. Blocks obtained
    from Disassembler.lift_trace() are owned by this object instead (there is
    no backing Graph) and are destroyed when it is garbage-collected / the
    context manager exits.
    """

    def __init__(self, ptr, owned=False):
        self._ptr = ptr
        self._owned = owned

    def __del__(self):
        if self._owned and self._ptr:
            lib.dragon_ignil_block_destroy(self._ptr)
        self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    @property
    def address(self):
        return lib.dragon_ignil_block_address(self._ptr)

    @property
    def size(self):
        return lib.dragon_ignil_block_size(self._ptr)

    def to_string(self):
        """Return a multi-line text rendering of all ops in this block."""
        raw = lib.dragon_ignil_block_to_string(self._ptr)
        try:
            return ffi.string(raw).decode()
        finally:
            lib.dragon_cstr_free(raw)

    def op_to_string(self, index):
        """Return the text rendering of the op at *index* (0-based)."""
        raw = lib.dragon_ignil_block_op_to_string(self._ptr, index)
        if raw == ffi.NULL:
            return None
        try:
            return ffi.string(raw).decode()
        finally:
            lib.dragon_cstr_free(raw)

    def ops(self):
        """Return a list of (op_addr, opcode_int, index) tuples for all ops."""
        result = []
        cb = ffi.callback(
            'void(uint64_t, dragon_ignil_opcode_t, size_t, void *)',
            lambda addr, opc, idx, _: result.append((addr, int(opc), idx))
        )
        lib.dragon_ignil_block_each_op(self._ptr, cb, ffi.NULL)
        return result

    def unlifted(self):
        """Machine addresses of the instructions the lifter had no semantics
        for, in order.

        Their register and flag results are UNDEF in the block - so nothing
        downstream is silently wrong - but an UNDEF that later dies is
        invisible, and an instruction whose only effect is a memory write
        leaves no op at all. Check this when the block has to be a complete
        account of the code, e.g. before trusting a symbolic run of it.
        simplify() and dead_store_eliminate() carry the list over."""
        count = int(lib.dragon_ignil_block_unlifted(self._ptr, ffi.NULL, 0))
        if count == 0:
            return []
        buf = ffi.new('uint64_t[]', count)
        lib.dragon_ignil_block_unlifted(self._ptr, buf, count)
        return [int(buf[i]) for i in range(count)]

    def simplify(self, max_iterations=0):
        """Peephole-simplify this block to a fixed point: constant
        folding/propagation, algebraic identity/annihilator elimination,
        no-op width-conversion elimination, and dead-Temp elimination.
        Block-local only — never crosses into predecessor/successor blocks,
        and never removes a Reg-defining op (a Reg may be live-out).

        Parameters
        ----------
        max_iterations : int
            Upper bound on fixed-point passes. 0 selects the library
            default (8).

        Returns
        -------
        (IGNILBlock, SimplifyStats)
            The simplified block is a new, independently owned IGNILBlock —
            this block is left untouched.
        """
        out_cf = ffi.new('size_t *')
        out_ia = ffi.new('size_t *')
        out_or = ffi.new('size_t *')
        out_it = ffi.new('size_t *')
        ptr = lib.dragon_ignil_simplify_block(
            self._ptr, max_iterations, out_cf, out_ia, out_or, out_it)
        stats = SimplifyStats(out_cf[0], out_ia[0], out_or[0], out_it[0])
        return IGNILBlock(ptr, owned=True), stats

    def dead_store_eliminate(self, arch, live_out=None):
        """Remove dead register and flag stores from this block by
        byte-precise backward liveness: a value written to a register that is
        overwritten before it is ever read, and is not live on exit, carries no
        information, so the op producing it is dropped.

        Overlapping sub-registers alias correctly — writing AX kills AL and AH
        but leaves the rest of RAX live. Unlike :meth:`simplify` this *does*
        remove Reg-defining ops, which is what collapses VM-protector junk;
        dead Temps go too, so a machine instruction whose only live effect was
        the removed register write disappears entirely. Side-effecting ops
        (STORE/CALL/JMP/CJMP/RET) are never removed.

        Parameters
        ----------
        arch : int
            An :class:`Architecture` value — the architecture this block was
            lifted for. Selects the register file used to resolve which bytes a
            32-bit write zero-extends over, so pass the right one: falling back
            (UNKNOWN, or an unsupported target) assumes an 8-byte parent, which
            is correct for x86-64 GPRs and AArch64 W registers but not for
            AArch64 S registers, which alias the 16-byte V registers.
        live_out : iterable of (offset, width), or None
            The registers observable after this block. ``None`` (the default)
            means "assume everything is live on exit": a store is then removed
            only when provably overwritten within this block before any read,
            which needs no ABI knowledge and is always safe. Passing a list
            means precisely those registers are live out, allowing more
            aggressive elimination (e.g. a RET-terminated block whose live-out
            is just the ABI return plus callee-saved registers) — correctness
            then rests on the list being sound.

        Returns
        -------
        (IGNILBlock, int)
            The new, independently owned block and the number of ops removed.
            This block is left untouched.
        """
        if live_out is None:
            regs, count = ffi.NULL, 0
        else:
            live_out = list(live_out)
            count = len(live_out)
            # An empty list is meaningful ("nothing is live out"), and differs
            # from None, so the pointer must stay non-NULL — allocate at least
            # one slot and let count carry the length.
            regs = ffi.new('dragon_ignil_reg_t[]', max(count, 1))
            for i, (offset, width) in enumerate(live_out):
                regs[i].offset = offset
                regs[i].width = width
        out_removed = ffi.new('size_t *')
        ptr = lib.dragon_ignil_dead_store_eliminate(
            self._ptr, arch, regs, count, out_removed)
        return IGNILBlock(ptr, owned=True), out_removed[0]

    def __repr__(self):
        return f'<IGNILBlock 0x{self.address:x} ops={self.size}>'


class SimplifyStats:
    """Counts from one IGNILBlock.simplify() call. Mirrors ignil::SimplifyStats."""

    def __init__(self, constants_folded, identities_applied, ops_removed, iterations):
        self.constants_folded = constants_folded
        self.identities_applied = identities_applied
        self.ops_removed = ops_removed
        self.iterations = iterations

    @property
    def changed(self):
        return bool(self.constants_folded or self.identities_applied or self.ops_removed)

    def __repr__(self):
        return (f'<SimplifyStats constants_folded={self.constants_folded} '
                f'identities_applied={self.identities_applied} '
                f'ops_removed={self.ops_removed} iterations={self.iterations}>')


# -- SliceExpr -----------------------------------------------------------------

class SliceExprType:
    """Mirror of dragon_slice_type_t."""
    CONST   = 0
    SYM_REG = 1
    BINOP   = 2
    UNARYOP = 3
    LOAD    = 4
    UNDEF   = 5


class SliceExpr:
    """Owned handle to a SliceExpr tree node.  Must be destroyed after use.
    Child nodes returned by left(), right(), operand(), load_addr() are also
    owned SliceExpr objects that must be destroyed independently."""

    def __init__(self, ptr):
        self._ptr = ptr

    def __del__(self):
        if self._ptr:
            lib.dragon_slice_expr_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    @property
    def type(self):
        """Return a SliceExprType constant."""
        return int(lib.dragon_slice_expr_type(self._ptr))

    def to_string(self):
        """Human-readable rendering of this expression tree."""
        raw = lib.dragon_slice_expr_to_string(self._ptr)
        try:
            return ffi.string(raw).decode()
        finally:
            lib.dragon_cstr_free(raw)

    def to_z3_string(self):
        """Lower this expression through Z3 and return the Z3 bitvector
        expression as a string.
        Raises RuntimeError if the library was built without Z3 support."""
        try:
            raw = lib.dragon_slice_expr_to_z3_string(self._ptr)
        except AttributeError:
            raise RuntimeError('dragon was built without Z3 support (-DDRAGON_USE_Z3=ON required)')
        try:
            return ffi.string(raw).decode()
        finally:
            lib.dragon_cstr_free(raw)

    def enumerate_values(self, max_values=0, sorted=True):
        """Enumerate concrete 64-bit values this expression can take, via Z3.

        Parameters
        ----------
        max_values : int
            Upper bound on results returned. 0 selects the library default (256).
        sorted : bool
            Sort results ascending (library default: True).

        Note: constructs its own Z3 context internally — there is no way to
        pass extra Z3 assertions across this boundary, unlike the C++ API's
        optional `constraints` parameter; use the C++ API directly if you
        need that.

        Raises RuntimeError if the library was built without Z3 support."""
        out_count = ffi.new('size_t *')
        try:
            ptr = lib.dragon_slice_expr_enumerate_values(
                self._ptr, max_values, 1 if sorted else 0, out_count)
        except AttributeError:
            raise RuntimeError('dragon was built without Z3 support (-DDRAGON_USE_Z3=ON required)')
        try:
            return [ptr[i] for i in range(out_count[0])]
        finally:
            lib.dragon_u64_array_free(ptr)

    def solve_unique(self):
        """Solve for a single concrete value this expression must take, via Z3.
        Returns None if zero or more than one model exists (unsatisfiable or
        underconstrained), the value itself if exactly one does.

        Raises RuntimeError if the library was built without Z3 support."""
        out_value = ffi.new('uint64_t *')
        try:
            found = lib.dragon_slice_expr_solve_unique(self._ptr, out_value)
        except AttributeError:
            raise RuntimeError('dragon was built without Z3 support (-DDRAGON_USE_Z3=ON required)')
        return out_value[0] if found else None

    # -- CONST

    @property
    def const_value(self):
        return lib.dragon_slice_expr_const_value(self._ptr)

    @property
    def const_width(self):
        return lib.dragon_slice_expr_const_width(self._ptr)

    # -- SYM_REG

    @property
    def symreg_offset(self):
        return lib.dragon_slice_expr_symreg_offset(self._ptr)

    @property
    def symreg_width(self):
        return lib.dragon_slice_expr_symreg_width(self._ptr)

    @property
    def symreg_name(self):
        """Register name if one was set, empty string otherwise."""
        return ffi.string(lib.dragon_slice_expr_symreg_name(self._ptr)).decode()

    # -- BINOP / UNARYOP

    @property
    def opcode(self):
        """Return the IGNILOpcode integer for BINOP or UNARYOP nodes."""
        return int(lib.dragon_slice_expr_opcode(self._ptr))

    @property
    def opcode_name(self):
        """Return the mnemonic string for the opcode."""
        return IGNILOpcode.name(self.opcode)

    def left(self):
        """Return the left child of a BINOP node (owned — caller must close/del)."""
        ptr = lib.dragon_slice_expr_left(self._ptr)
        return SliceExpr(ptr) if ptr != ffi.NULL else None

    def right(self):
        """Return the right child of a BINOP node (owned — caller must close/del)."""
        ptr = lib.dragon_slice_expr_right(self._ptr)
        return SliceExpr(ptr) if ptr != ffi.NULL else None

    def operand(self):
        """Return the child of a UNARYOP node (owned — caller must close/del)."""
        ptr = lib.dragon_slice_expr_operand(self._ptr)
        return SliceExpr(ptr) if ptr != ffi.NULL else None

    # -- LOAD

    def load_addr(self):
        """Return the address sub-expression of a LOAD node (owned)."""
        ptr = lib.dragon_slice_expr_load_addr(self._ptr)
        return SliceExpr(ptr) if ptr != ffi.NULL else None

    @property
    def load_width(self):
        return lib.dragon_slice_expr_load_width(self._ptr)

    def __repr__(self):
        return f'<SliceExpr {self.to_string()}>'


# -- BackwardSlicer ------------------------------------------------------------

class BackwardSlicer:
    """Slices register values backwards through an IGNIL CFG.

    Parameters
    ----------
    max_blocks : int
        Maximum number of inter-block steps (default 5).
        The slicer stops at join nodes regardless of this limit.
    """

    def __init__(self, max_blocks=5):
        self._ptr = lib.dragon_slicer_create(max_blocks)
        if self._ptr == ffi.NULL:
            raise RuntimeError('failed to create BackwardSlicer')

    def __del__(self):
        if self._ptr:
            lib.dragon_slicer_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    def slice_reg(self, graph, block_addr, reg_offset, reg_width, reg_name=''):
        """Slice a register backwards through the CFG of *graph*.

        Parameters
        ----------
        graph      : Graph
            A fully lifted graph (produced by Disassembler.analyze).
        block_addr : int
            Address of the block where slicing starts.
        reg_offset : int
            Byte offset of the register in the IGNIL register space.
        reg_width  : int
            Bit width of the register.
        reg_name   : str
            Optional human-readable name carried into SymReg results when
            the value cannot be resolved.  Pass via ``*x86.RAX`` to have
            names filled in automatically.

        Returns
        -------
        SliceExpr
            Owned expression tree (caller must destroy / use as context manager).
        """
        name_bytes = reg_name.encode() if reg_name else ffi.NULL
        ptr = lib.dragon_slicer_slice_reg(
            self._ptr, graph._ptr, block_addr, reg_offset, reg_width,
            name_bytes)
        if ptr == ffi.NULL:
            raise RuntimeError('slicer returned NULL')
        return SliceExpr(ptr)

    def __repr__(self):
        return '<BackwardSlicer>'


# -- SwitchDetector --------------------------------------------------------------

class SwitchCandidate:
    """Everything extracted from a recognized jump-table dispatch pattern.
    Mirrors dragon_switch_candidate_t — construct via detect_possible_switch(),
    not directly.

    index_reg_offset/index_reg_width identify the index register in the
    IGNIL register address space (see x86/arm register descriptors below),
    the same convention BackwardSlicer.slice_reg() uses.
    """

    def __init__(self, table_base, entry_size, num_cases,
                 index_reg_offset, index_reg_width):
        self.table_base = table_base
        self.entry_size = entry_size
        self.num_cases = num_cases
        self.index_reg_offset = index_reg_offset
        self.index_reg_width = index_reg_width

    def __repr__(self):
        return (f'<SwitchCandidate table_base=0x{self.table_base:x} '
                f'entry_size={self.entry_size} num_cases={self.num_cases}>')


def detect_possible_switch(jump_target, block_addr, graph):
    """Inspect a backward-slice result (typically from
    BackwardSlicer.slice_reg() on an indirect jump's target) and determine
    whether it is a jump-table indirect branch.

    Parameters
    ----------
    jump_target : SliceExpr
    block_addr  : int
        Address of the block containing the indirect jump.
    graph       : Graph

    Returns
    -------
    SwitchCandidate or None
        None if the pattern didn't match. A returned candidate with
        num_cases == 0 means the pattern matched but the bounds guard
        wasn't found.
    """
    out = ffi.new('dragon_switch_candidate_t *')
    matched = lib.dragon_detect_possible_switch(
        jump_target._ptr, block_addr, graph._ptr, out)
    if not matched:
        return None
    return SwitchCandidate(out.table_base, out.entry_size, out.num_cases,
                            out.index_reg_offset, out.index_reg_width)


def read_table_targets(candidate, data, base_addr):
    """Read candidate.num_cases pointer-sized little-endian entries from the
    jump table *candidate* describes.

    Parameters
    ----------
    candidate : SwitchCandidate
    data      : bytes-like
        Buffer starting at *base_addr* in the binary's address space (not
        necessarily starting at candidate.table_base — the table is
        located within this window using its own address).
    base_addr : int
        Address the first byte of *data* corresponds to.

    Returns
    -------
    list[int]
        Empty if num_cases == 0 or the table extends outside *data*.
    """
    buf = ffi.from_buffer(data)
    out_count = ffi.new('size_t *')
    sw = ffi.new('dragon_switch_candidate_t *')
    sw.table_base = candidate.table_base
    sw.entry_size = candidate.entry_size
    sw.num_cases = candidate.num_cases
    sw.index_reg_offset = candidate.index_reg_offset
    sw.index_reg_width = candidate.index_reg_width
    ptr = lib.dragon_read_table_targets(sw, buf, len(data), base_addr, out_count)
    try:
        return [ptr[i] for i in range(out_count[0])]
    finally:
        lib.dragon_u64_array_free(ptr)


# -- LLVMLifter ----------------------------------------------------------------

class LLVMLifter:
    """Lifts Functions to LLVM IR via the IGNIL graph.

    Parameters
    ----------
    arch        : Architecture
        Target architecture (default X86_64).
    module_name : str
        Name embedded in the LLVM module (default 'lifted').
    """

    def __init__(self, arch=Architecture.X86_64, module_name='lifted'):
        self._ptr = lib.dragon_llvm_lifter_create(arch, module_name.encode())
        if self._ptr == ffi.NULL:
            raise RuntimeError('failed to create LLVMLifter')

    def __del__(self):
        if self._ptr:
            lib.dragon_llvm_lifter_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    def lift(self, function, graph):
        """Lift *function* using its IGNIL blocks in *graph*.

        Returns True on success; False if any IGNIL block is missing.
        """
        return bool(lib.dragon_llvm_lifter_lift(
            self._ptr, function._ptr, graph._ptr))

    def lift_expression(self, expression, arguments, name='recovered'):
        """Lower an actual recovered SymExpr DAG to a typed pure LLVM function.

        All free dependencies must be distinct named Bool/BitVec arguments from
        the same context. Unknown memory, opaque calls and UNDEF are rejected,
        not zero-filled or solver-concretized. Bit-vector shifts retain total
        SMT semantics even for amounts >= width (no LLVM poison shortcut).
        This projects the return value, not memory effects or all-path behavior.
        Capture/path assumptions remain the caller's responsibility.
        """
        arguments = list(arguments)
        native = ffi.new('const dragon_symexpr_t*[]',
                         [arg._handle() for arg in arguments]) if arguments else ffi.NULL
        return bool(lib.dragon_llvm_lifter_lift_expression(
            self._ptr, expression._handle(), native, len(arguments), name.encode()))

    def lift_expression_calls(self, expression, arguments, calls, name='recovered'):
        """Lower explicit scalar call results; callees must already be defined.

        Calls are topologically ordered dictionaries containing result,
        function (the LLVM name), and arguments. Callees receive noinline so
        normal O2 keeps the recovered boundary visible.
        """
        def array(values):
            return ffi.new('const dragon_symexpr_t*[]',
                           [v._handle() for v in values]) if values else ffi.NULL
        arguments, calls = list(arguments), list(calls)
        native = array(arguments)
        records = ffi.new('dragon_expression_call_t[]', len(calls)) if calls else ffi.NULL
        keepalive = []
        for i, call in enumerate(calls):
            actual = array(list(call['arguments']))
            function = ffi.new('char[]', call['function'].encode())
            keepalive.extend((actual, function))
            records[i].result = call['result']._handle()
            records[i].function = function
            records[i].arguments = actual
            records[i].argument_count = len(call['arguments'])
        return bool(lib.dragon_llvm_lifter_lift_expression_calls(
            self._ptr, expression._handle(), native, len(arguments), name.encode(),
            records, len(calls)))

    def lift_loop_region(self, inputs, carried, next_values, continuation, name='loop_region'):
        """Export actual transition DAGs with simultaneous loop PHIs.

        while continuation(state, inputs): state = next_values(state, inputs).
        Returns the header state, not the final native function return. Entry
        invariant/termination and the exit projection remain caller obligations.
        """
        inputs, carried, next_values = list(inputs), list(carried), list(next_values)
        if len(carried) != len(next_values):
            raise ValueError('loop state/update count mismatch')
        def array(values):
            return ffi.new('const dragon_symexpr_t*[]', [v._handle() for v in values]) if values else ffi.NULL
        return bool(lib.dragon_llvm_lifter_lift_loop_region(self._ptr, array(inputs), len(inputs),
                    array(carried), array(next_values), len(carried), continuation._handle(), name.encode()))

    def lift_loop_function(self, inputs, carried, initial, next_values,
                           continuation, returned, name='recovered_loop', *,
                           entry_guard=None, otherwise=None):
        """Build actual simultaneous PHIs with input-only seeds and a return.

        Inputs are noundef concrete words (the Z3 bit-vector domain), not LLVM
        undef/poison. No fixed trip count/affine counter or termination assumption.
        Optional entry_guard/otherwise emit a real outer branch. Pure return projection;
        caller supplies reachability/semantic proofs and any memory effects.
        """
        inputs, carried = list(inputs), list(carried)
        initial, next_values = list(initial), list(next_values)
        if len(carried) != len(initial) or len(carried) != len(next_values):
            raise ValueError('loop state/seed/update count mismatch')
        if (entry_guard is None) != (otherwise is None):
            raise ValueError('entry_guard and otherwise must be supplied together')
        def array(values):
            return ffi.new('const dragon_symexpr_t*[]', [v._handle() for v in values]) if values else ffi.NULL
        return bool(lib.dragon_llvm_lifter_lift_loop_function(self._ptr,
            array(inputs), len(inputs), array(carried), array(initial), array(next_values), len(carried),
            continuation._handle(), returned._handle(),
            entry_guard._handle() if entry_guard is not None else ffi.NULL,
            otherwise._handle() if otherwise is not None else ffi.NULL, name.encode()))

    def lift_effects(self, executor, expression, arguments, *, pointers=(), name='recovered'):
        """Export ordered memory effects and a return expression (None = void).

        Enable executor.enable_memory_effects() before running the resolved path.
        `pointers` are argument indices exported as ptr (source symbols BV64).
        No pointer-separation assumption is made. Every IGNIL LOAD/STORE is
        represented, including writes irrelevant to the return value. Unknown
        dependencies fail. This is a finite-path projection, not CFG recovery.
        Valid ordinary nonvolatile memory only; not faults/atomics/concurrency.
        """
        arguments, pointers = list(arguments), set(pointers)
        if any(not isinstance(i, int) or i < 0 or i >= len(arguments) for i in pointers):
            raise ValueError('pointer index outside argument list')
        native = ffi.new('const dragon_symexpr_t*[]',
                         [a._handle() for a in arguments]) if arguments else ffi.NULL
        flags = ffi.new('int[]', [int(i in pointers) for i in range(len(arguments))]) if arguments else ffi.NULL
        return bool(lib.dragon_llvm_lifter_lift_effects(
            self._ptr, executor._handle(), expression._handle() if expression is not None else ffi.NULL,
            native, flags, len(arguments), name.encode()))

    def lift_path(self, steps, name='resolved_path'):
        """Lift an x86-64 symbolically resolved finite path using actual IGNIL.

        Each step is a dict with body (IGNILBlock or None), address,
        next_address, transfer ('next', 'call', 'return'), and optional
        return_address / stack_adjustment. Repeated PCs are separate contexts.
        Branch/return targets become llvm.assume guards; CALL/RET stack effects
        are modeled, not external calls or premature LLVM returns. The final
        step must return. Bodies stay borrowed only for the duration of this call.
        This retains the (mem, regs) interface and embeds neither capture bytes
        nor concrete CPUID/timing samples. It is not an all-path CFG recovery.
        """
        steps = list(steps)
        if not steps:
            return False
        native = ffi.new('dragon_llvm_path_step_t[]', len(steps))
        transfers = {'next': 0, 'call': 1, 'return': 2}
        for dst, step in zip(native, steps):
            body = step.get('body')
            dst.body = body._ptr if body is not None else ffi.NULL
            dst.address = step['address']
            dst.next_address = step['next_address']
            dst.transfer = transfers[step.get('transfer', 'next')]
            dst.return_address = step.get('return_address', 0)
            dst.stack_adjustment = step.get('stack_adjustment', 0)
        return bool(lib.dragon_llvm_lifter_lift_path(
            self._ptr, native, len(steps), name.encode()))

    def ir(self):
        """Return the textual LLVM IR for all lifted functions."""
        raw = lib.dragon_llvm_lifter_ir(self._ptr)
        try:
            return ffi.string(raw).decode()
        finally:
            lib.dragon_cstr_free(raw)

    def run_mem2reg(self):
        """Promote allocas to SSA values."""
        lib.dragon_llvm_lifter_run_mem2reg(self._ptr)

    def run_inst_combine(self):
        """Fold sub-register mask/OR patterns."""
        lib.dragon_llvm_lifter_run_inst_combine(self._ptr)

    def run_gvn(self):
        """Eliminate redundant loads."""
        lib.dragon_llvm_lifter_run_gvn(self._ptr)

    def run_dce(self):
        """Remove dead flag computations."""
        lib.dragon_llvm_lifter_run_dce(self._ptr)

    def load_ir(self, text):
        """Import verified LLVM IR, keeping the previous module on failure."""
        return bool(lib.dragon_llvm_lifter_load_ir(self._ptr, text.encode()))

    def run_loop_reroll(self):
        """Post-O2 exact scalar recurrence matching -> fixed-trip counted loops.

        Returns the loop count. No parameter-bound loop discovery, memory/call
        folding, VM identification, sampled inputs or source algorithm template.
        """
        return int(lib.dragon_llvm_lifter_run_loop_reroll(self._ptr))

    def _check_llvm(self, operation, *args):
        error = ffi.new('char**')
        try:
            if not operation(self._ptr or ffi.NULL, *args, error):
                diagnostic = ffi.string(error[0]).decode() if error[0] != ffi.NULL else 'LLVM operation failed'
                raise ValueError(diagnostic)
        finally:
            if error[0] != ffi.NULL:
                lib.dragon_cstr_free(error[0])
        return True

    @property
    def llvm_version(self):
        """Version of the LLVM linked into libdragon (not the system opt)."""
        return ffi.string(lib.dragon_llvm_version()).decode()

    def verify(self):
        """In-process LLVM structural verification; raises ValueError on failure.

        Not a return-value, memory-effect or native-equivalence proof.
        """
        return self._check_llvm(lib.dragon_llvm_lifter_verify)

    def run_pass_pipeline(self, pipeline):
        """Run LLVM PassBuilder syntax in the library, without an opt process.

        E.g. 'default<O2>' or 'function(instcombine,early-cse,dce)'. Parse and
        verify errors raise ValueError and preserve the original module. A
        verified clone is committed on success; semantic proofs remain separate.
        """
        if not isinstance(pipeline, str) or not pipeline or '\0' in pipeline:
            raise ValueError('pipeline must be a nonempty string without NUL')
        return self._check_llvm(lib.dragon_llvm_lifter_run_pass_pipeline, pipeline.encode())

    def optimize(self, pipeline=None):
        """Run the legacy pass sequence, or an explicit LLVM PassBuilder pipeline.

        No argument retains mem2reg → instcombine → GVN → DCE (not O2).
        Use optimize('default<O2>') for the in-process LLVM O2 pipeline.
        'dragon-scalar-o2' uses O2 without SLP/loop vectorization; the ordinary
        O2 pipeline is unchanged. 'function(dragon-clean-words,instcombine,dce)'
        reconstructs sign extensions and removes redundant zero-count guards
        on same-input funnel rotations. Independent equivalence is separate.
        """
        return self.run_pass_pipeline(
            'function(mem2reg,instcombine,gvn,dce)' if pipeline is None else pipeline)

    def __repr__(self):
        return '<LLVMLifter>'


# -- FLIRT signatures (dragon::sigs) --------------------------------------------

def sigs_crc16(data):
    """Compute dragon-tales' signature CRC16 (reflected, poly 0xA001, init
    0xFFFF, no final XOR — CRC-16/ARC) over *data*.

    Caveat: this variant was never verified against a real IDA/FLAIR-generated
    .pat file — see SignatureDB's class doc.
    """
    buf = ffi.from_buffer(data)
    return lib.dragon_sigs_crc16(buf, len(data))


class SignatureDB:
    """A loaded collection of FLIRT .pat signatures, ready for matching."""

    def __init__(self):
        self._ptr = lib.dragon_sigdb_create()
        if self._ptr == ffi.NULL:
            raise RuntimeError('failed to create SignatureDB')

    def __del__(self):
        if self._ptr:
            lib.dragon_sigdb_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    def load_directory(self, path):
        """Load and append every .pat file directly inside *path* (not
        recursive). Files that fail to parse are silently skipped — compare
        signature_count() before/after to see how much was actually loaded."""
        lib.dragon_sigdb_load_directory(self._ptr, str(path).encode())

    def load_file(self, path):
        """Load and append a single .pat file. No-op if it can't be parsed."""
        lib.dragon_sigdb_load_file(self._ptr, str(path).encode())

    @property
    def signature_count(self):
        return lib.dragon_sigdb_signature_count(self._ptr)

    def match_at(self, data, address):
        """Try every signature against *data*, which must begin at the
        candidate function's address. Returns the first match as a
        (address, name, length) tuple, or None if nothing matched."""
        buf = ffi.from_buffer(data)
        out_address = ffi.new('uint64_t *')
        out_name = ffi.new('char **')
        out_length = ffi.new('uint32_t *')
        matched = lib.dragon_sigdb_match_at(
            self._ptr, buf, len(data), address,
            out_address, out_name, out_length)
        if not matched:
            return None
        try:
            name = ffi.string(out_name[0]).decode()
        finally:
            lib.dragon_cstr_free(out_name[0])
        return (out_address[0], name, out_length[0])

    def match_entries(self, image, image_base, entry_points):
        """Try every address in *entry_points* against every signature.
        *image*/*image_base* describe the byte region the entry points fall
        within. Unlike match_at, every name a matching signature defines is
        reported (a module can bundle more than one function/offset under
        one pattern), so one entry point may produce more than one match.

        Returns a list of (address, name, length) tuples.
        """
        buf = ffi.from_buffer(image)
        entries = ffi.new('uint64_t[]', entry_points) if entry_points else ffi.NULL
        result = []
        cb = ffi.callback(
            'void(uint64_t, const char *, uint32_t, void *)',
            lambda addr, name, length, _: result.append(
                (addr, ffi.string(name).decode(), length))
        )
        lib.dragon_sigdb_match_entries(
            self._ptr, buf, len(image), image_base,
            entries, len(entry_points), cb, ffi.NULL)
        return result

    def __repr__(self):
        return f'<SignatureDB signatures={self.signature_count}>'


# -- x86 register descriptors --------------------------------------------------

class x86:
    """x86 / x86-64 IGNIL register descriptors as (offset, width, name) tuples.

    Usage::

        slicer.slice_reg(graph, block_addr, *x86.RAX)
        # equivalent to: slice_reg(graph, block_addr, 0, 64, 'RAX')

    The name is carried into SymReg results and printed in to_string() output
    when the slicer cannot resolve the register to a concrete value.

    Layout (byte offsets in the IGNIL register address space):
        RAX=0  RCX=8  RDX=16  RBX=24  RSP=32  RBP=40  RSI=48  RDI=56
        R8=64 ... R15=120  RIP=128
        CF=136  PF=137  AF=138  ZF=139  SF=140  OF=141  DF=142
        XMM0..XMM15 low64 = 143 + 8*i; high64 = 288 + 8*i
        FSBASE=272  GSBASE=280 (long-mode bases, not segment selectors)
    """

    # 64-bit GP registers
    RAX = (0,   64, 'RAX'); RCX = (8,   64, 'RCX'); RDX = (16,  64, 'RDX'); RBX = (24,  64, 'RBX')
    RSP = (32,  64, 'RSP'); RBP = (40,  64, 'RBP'); RSI = (48,  64, 'RSI'); RDI = (56,  64, 'RDI')
    R8  = (64,  64, 'R8');  R9  = (72,  64, 'R9');  R10 = (80,  64, 'R10'); R11 = (88,  64, 'R11')
    R12 = (96,  64, 'R12'); R13 = (104, 64, 'R13'); R14 = (112, 64, 'R14'); R15 = (120, 64, 'R15')
    RIP = (128, 64, 'RIP')

    # 32-bit GP registers
    EAX  = (0,   32, 'EAX');  ECX  = (8,   32, 'ECX');  EDX  = (16,  32, 'EDX');  EBX  = (24,  32, 'EBX')
    ESP  = (32,  32, 'ESP');  EBP  = (40,  32, 'EBP');  ESI  = (48,  32, 'ESI');  EDI  = (56,  32, 'EDI')
    R8D  = (64,  32, 'R8D');  R9D  = (72,  32, 'R9D');  R10D = (80,  32, 'R10D'); R11D = (88,  32, 'R11D')
    R12D = (96,  32, 'R12D'); R13D = (104, 32, 'R13D'); R14D = (112, 32, 'R14D'); R15D = (120, 32, 'R15D')

    # 16-bit GP registers
    AX = (0,  16, 'AX'); CX = (8,  16, 'CX'); DX = (16, 16, 'DX'); BX = (24, 16, 'BX')
    SP = (32, 16, 'SP'); BP = (40, 16, 'BP'); SI = (48, 16, 'SI'); DI = (56, 16, 'DI')

    # 8-bit low GP registers
    AL  = (0,  8, 'AL');  CL  = (8,  8, 'CL');  DL  = (16, 8, 'DL');  BL  = (24, 8, 'BL')
    SPL = (32, 8, 'SPL'); BPL = (40, 8, 'BPL'); SIL = (48, 8, 'SIL'); DIL = (56, 8, 'DIL')
    # 8-bit high registers (legacy aliases)
    AH = (1,  8, 'AH'); CH = (9,  8, 'CH'); DH = (17, 8, 'DH'); BH = (25, 8, 'BH')

    # EFLAGS — 8-bit slots in the IGNIL register space (x86registers.def uses width=8)
    CF = (136, 8, 'CF'); PF = (137, 8, 'PF'); AF = (138, 8, 'AF'); ZF = (139, 8, 'ZF')
    SF = (140, 8, 'SF'); OF = (141, 8, 'OF'); DF = (142, 8, 'DF')

    FSBASE = (272, 64, 'FSBASE'); GSBASE = (280, 64, 'GSBASE')

    # Complete XMM state as two ABI-stable 64-bit banks.
    REGISTER_FILE_BYTES = 416
    XMM0 = (143, 64, 'XMM0'); XMM0_HI = (288, 64, 'XMM0_HI')
    XMM1 = (151, 64, 'XMM1'); XMM1_HI = (296, 64, 'XMM1_HI')
    XMM2 = (159, 64, 'XMM2'); XMM2_HI = (304, 64, 'XMM2_HI')
    XMM3 = (167, 64, 'XMM3'); XMM3_HI = (312, 64, 'XMM3_HI')
    XMM4 = (175, 64, 'XMM4'); XMM4_HI = (320, 64, 'XMM4_HI')
    XMM5 = (183, 64, 'XMM5'); XMM5_HI = (328, 64, 'XMM5_HI')
    XMM6 = (191, 64, 'XMM6'); XMM6_HI = (336, 64, 'XMM6_HI')
    XMM7 = (199, 64, 'XMM7'); XMM7_HI = (344, 64, 'XMM7_HI')
    XMM8 = (207, 64, 'XMM8'); XMM8_HI = (352, 64, 'XMM8_HI')
    XMM9 = (215, 64, 'XMM9'); XMM9_HI = (360, 64, 'XMM9_HI')
    XMM10 = (223, 64, 'XMM10'); XMM10_HI = (368, 64, 'XMM10_HI')
    XMM11 = (231, 64, 'XMM11'); XMM11_HI = (376, 64, 'XMM11_HI')
    XMM12 = (239, 64, 'XMM12'); XMM12_HI = (384, 64, 'XMM12_HI')
    XMM13 = (247, 64, 'XMM13'); XMM13_HI = (392, 64, 'XMM13_HI')
    XMM14 = (255, 64, 'XMM14'); XMM14_HI = (400, 64, 'XMM14_HI')
    XMM15 = (263, 64, 'XMM15'); XMM15_HI = (408, 64, 'XMM15_HI')



# -- AArch64 register descriptors -----------------------------------------------

class arm:
    """AArch64 IGNIL register descriptors as (offset, width, name) tuples.

    Usage::

        slicer.slice_reg(graph, block_addr, *arm.X0)
        # equivalent to: slice_reg(graph, block_addr, 0, 64, 'X0')

    The name is carried into SymReg results and printed in to_string() output
    when the slicer cannot resolve the register to a concrete value.

    Layout (byte offsets in the IGNIL register address space):
        X0=0  X1=8  X2=16 ... X28=224  X29(FP)=232  X30(LR)=240
        XZR=248  SP=256  PC=264
        V0..V31=272..768 (16 bytes each)
        NF=784  ZF=785  CF=786  VF=787
    """

    # 64-bit general-purpose registers
    X0  = (0,   64, 'X0');  X1  = (8,   64, 'X1');  X2  = (16,  64, 'X2');  X3  = (24,  64, 'X3')
    X4  = (32,  64, 'X4');  X5  = (40,  64, 'X5');  X6  = (48,  64, 'X6');  X7  = (56,  64, 'X7')
    X8  = (64,  64, 'X8');  X9  = (72,  64, 'X9');  X10 = (80,  64, 'X10'); X11 = (88,  64, 'X11')
    X12 = (96,  64, 'X12'); X13 = (104, 64, 'X13'); X14 = (112, 64, 'X14'); X15 = (120, 64, 'X15')
    X16 = (128, 64, 'X16'); X17 = (136, 64, 'X17'); X18 = (144, 64, 'X18'); X19 = (152, 64, 'X19')
    X20 = (160, 64, 'X20'); X21 = (168, 64, 'X21'); X22 = (176, 64, 'X22'); X23 = (184, 64, 'X23')
    X24 = (192, 64, 'X24'); X25 = (200, 64, 'X25'); X26 = (208, 64, 'X26'); X27 = (216, 64, 'X27')
    X28 = (224, 64, 'X28'); X29 = (232, 64, 'X29'); X30 = (240, 64, 'X30'); XZR = (248, 64, 'XZR')
    SP  = (256, 64, 'SP');  PC  = (264, 64, 'PC')

    # Aliases for the frame pointer / link register
    FP = (232, 64, 'FP'); LR = (240, 64, 'LR')

    # 32-bit views (lower half of each X register)
    W0  = (0,   32, 'W0');  W1  = (8,   32, 'W1');  W2  = (16,  32, 'W2');  W3  = (24,  32, 'W3')
    W4  = (32,  32, 'W4');  W5  = (40,  32, 'W5');  W6  = (48,  32, 'W6');  W7  = (56,  32, 'W7')
    W8  = (64,  32, 'W8');  W9  = (72,  32, 'W9');  W10 = (80,  32, 'W10'); W11 = (88,  32, 'W11')
    W12 = (96,  32, 'W12'); W13 = (104, 32, 'W13'); W14 = (112, 32, 'W14'); W15 = (120, 32, 'W15')
    W16 = (128, 32, 'W16'); W17 = (136, 32, 'W17'); W18 = (144, 32, 'W18'); W19 = (152, 32, 'W19')
    W20 = (160, 32, 'W20'); W21 = (168, 32, 'W21'); W22 = (176, 32, 'W22'); W23 = (184, 32, 'W23')
    W24 = (192, 32, 'W24'); W25 = (200, 32, 'W25'); W26 = (208, 32, 'W26'); W27 = (216, 32, 'W27')
    W28 = (224, 32, 'W28'); W29 = (232, 32, 'W29'); W30 = (240, 32, 'W30'); WZR = (248, 32, 'WZR')
    WSP = (256, 32, 'WSP')

    # NEON/FP vector registers — V/Q share the 128-bit slot; D/S/H/B select
    # progressively smaller slices of the same offset.
    V0  = (272,  128, 'V0');  V1  = (288,  128, 'V1');  V2  = (304,  128, 'V2');  V3  = (320,  128, 'V3')
    V4  = (336,  128, 'V4');  V5  = (352,  128, 'V5');  V6  = (368,  128, 'V6');  V7  = (384,  128, 'V7')
    V8  = (400,  128, 'V8');  V9  = (416,  128, 'V9');  V10 = (432,  128, 'V10'); V11 = (448,  128, 'V11')
    V12 = (464,  128, 'V12'); V13 = (480,  128, 'V13'); V14 = (496,  128, 'V14'); V15 = (512,  128, 'V15')
    V16 = (528,  128, 'V16'); V17 = (544,  128, 'V17'); V18 = (560,  128, 'V18'); V19 = (576,  128, 'V19')
    V20 = (592,  128, 'V20'); V21 = (608,  128, 'V21'); V22 = (624,  128, 'V22'); V23 = (640,  128, 'V23')
    V24 = (656,  128, 'V24'); V25 = (672,  128, 'V25'); V26 = (688,  128, 'V26'); V27 = (704,  128, 'V27')
    V28 = (720,  128, 'V28'); V29 = (736,  128, 'V29'); V30 = (752,  128, 'V30'); V31 = (768,  128, 'V31')

    Q0  = (272,  128, 'Q0');  Q1  = (288,  128, 'Q1');  Q2  = (304,  128, 'Q2');  Q3  = (320,  128, 'Q3')
    Q4  = (336,  128, 'Q4');  Q5  = (352,  128, 'Q5');  Q6  = (368,  128, 'Q6');  Q7  = (384,  128, 'Q7')
    Q8  = (400,  128, 'Q8');  Q9  = (416,  128, 'Q9');  Q10 = (432,  128, 'Q10'); Q11 = (448,  128, 'Q11')
    Q12 = (464,  128, 'Q12'); Q13 = (480,  128, 'Q13'); Q14 = (496,  128, 'Q14'); Q15 = (512,  128, 'Q15')
    Q16 = (528,  128, 'Q16'); Q17 = (544,  128, 'Q17'); Q18 = (560,  128, 'Q18'); Q19 = (576,  128, 'Q19')
    Q20 = (592,  128, 'Q20'); Q21 = (608,  128, 'Q21'); Q22 = (624,  128, 'Q22'); Q23 = (640,  128, 'Q23')
    Q24 = (656,  128, 'Q24'); Q25 = (672,  128, 'Q25'); Q26 = (688,  128, 'Q26'); Q27 = (704,  128, 'Q27')
    Q28 = (720,  128, 'Q28'); Q29 = (736,  128, 'Q29'); Q30 = (752,  128, 'Q30'); Q31 = (768,  128, 'Q31')

    D0  = (272,  64, 'D0');  D1  = (288,  64, 'D1');  D2  = (304,  64, 'D2');  D3  = (320,  64, 'D3')
    D4  = (336,  64, 'D4');  D5  = (352,  64, 'D5');  D6  = (368,  64, 'D6');  D7  = (384,  64, 'D7')
    D8  = (400,  64, 'D8');  D9  = (416,  64, 'D9');  D10 = (432,  64, 'D10'); D11 = (448,  64, 'D11')
    D12 = (464,  64, 'D12'); D13 = (480,  64, 'D13'); D14 = (496,  64, 'D14'); D15 = (512,  64, 'D15')
    D16 = (528,  64, 'D16'); D17 = (544,  64, 'D17'); D18 = (560,  64, 'D18'); D19 = (576,  64, 'D19')
    D20 = (592,  64, 'D20'); D21 = (608,  64, 'D21'); D22 = (624,  64, 'D22'); D23 = (640,  64, 'D23')
    D24 = (656,  64, 'D24'); D25 = (672,  64, 'D25'); D26 = (688,  64, 'D26'); D27 = (704,  64, 'D27')
    D28 = (720,  64, 'D28'); D29 = (736,  64, 'D29'); D30 = (752,  64, 'D30'); D31 = (768,  64, 'D31')

    S0  = (272,  32, 'S0');  S1  = (288,  32, 'S1');  S2  = (304,  32, 'S2');  S3  = (320,  32, 'S3')
    S4  = (336,  32, 'S4');  S5  = (352,  32, 'S5');  S6  = (368,  32, 'S6');  S7  = (384,  32, 'S7')
    S8  = (400,  32, 'S8');  S9  = (416,  32, 'S9');  S10 = (432,  32, 'S10'); S11 = (448,  32, 'S11')
    S12 = (464,  32, 'S12'); S13 = (480,  32, 'S13'); S14 = (496,  32, 'S14'); S15 = (512,  32, 'S15')
    S16 = (528,  32, 'S16'); S17 = (544,  32, 'S17'); S18 = (560,  32, 'S18'); S19 = (576,  32, 'S19')
    S20 = (592,  32, 'S20'); S21 = (608,  32, 'S21'); S22 = (624,  32, 'S22'); S23 = (640,  32, 'S23')
    S24 = (656,  32, 'S24'); S25 = (672,  32, 'S25'); S26 = (688,  32, 'S26'); S27 = (704,  32, 'S27')
    S28 = (720,  32, 'S28'); S29 = (736,  32, 'S29'); S30 = (752,  32, 'S30'); S31 = (768,  32, 'S31')

    H0  = (272,  16, 'H0');  H1  = (288,  16, 'H1');  H2  = (304,  16, 'H2');  H3  = (320,  16, 'H3')
    H4  = (336,  16, 'H4');  H5  = (352,  16, 'H5');  H6  = (368,  16, 'H6');  H7  = (384,  16, 'H7')
    H8  = (400,  16, 'H8');  H9  = (416,  16, 'H9');  H10 = (432,  16, 'H10'); H11 = (448,  16, 'H11')
    H12 = (464,  16, 'H12'); H13 = (480,  16, 'H13'); H14 = (496,  16, 'H14'); H15 = (512,  16, 'H15')
    H16 = (528,  16, 'H16'); H17 = (544,  16, 'H17'); H18 = (560,  16, 'H18'); H19 = (576,  16, 'H19')
    H20 = (592,  16, 'H20'); H21 = (608,  16, 'H21'); H22 = (624,  16, 'H22'); H23 = (640,  16, 'H23')
    H24 = (656,  16, 'H24'); H25 = (672,  16, 'H25'); H26 = (688,  16, 'H26'); H27 = (704,  16, 'H27')
    H28 = (720,  16, 'H28'); H29 = (736,  16, 'H29'); H30 = (752,  16, 'H30'); H31 = (768,  16, 'H31')

    B0  = (272,  8, 'B0');  B1  = (288,  8, 'B1');  B2  = (304,  8, 'B2');  B3  = (320,  8, 'B3')
    B4  = (336,  8, 'B4');  B5  = (352,  8, 'B5');  B6  = (368,  8, 'B6');  B7  = (384,  8, 'B7')
    B8  = (400,  8, 'B8');  B9  = (416,  8, 'B9');  B10 = (432,  8, 'B10'); B11 = (448,  8, 'B11')
    B12 = (464,  8, 'B12'); B13 = (480,  8, 'B13'); B14 = (496,  8, 'B14'); B15 = (512,  8, 'B15')
    B16 = (528,  8, 'B16'); B17 = (544,  8, 'B17'); B18 = (560,  8, 'B18'); B19 = (576,  8, 'B19')
    B20 = (592,  8, 'B20'); B21 = (608,  8, 'B21'); B22 = (624,  8, 'B22'); B23 = (640,  8, 'B23')
    B24 = (656,  8, 'B24'); B25 = (672,  8, 'B25'); B26 = (688,  8, 'B26'); B27 = (704,  8, 'B27')
    B28 = (720,  8, 'B28'); B29 = (736,  8, 'B29'); B30 = (752,  8, 'B30'); B31 = (768,  8, 'B31')

    # NZCV condition flags — "VF" avoids collision with the V register prefix.
    NF = (784, 8, 'NF'); ZF = (785, 8, 'ZF'); CF = (786, 8, 'CF'); VF = (787, 8, 'VF')


# -- IGNIL symbolic execution ---------------------------------------------------

class SymExecStatus:
    """Mirror of ignil::ExecStatus."""
    OK = 0
    MALFORMED_OP = 1
    UNSUPPORTED_OP = 2
    SOLVER_FAILURE = 3


class SymExit:
    """Mirror of ignil::ExitKind — how a block left control flow."""
    FALLTHROUGH = 0
    JUMP = 1
    CONDITIONAL_JUMP = 2
    CALL = 3
    RETURN = 4
    ERROR = 5


class _SymOp:
    ADD = 0; SUB = 1; MUL = 2; AND = 3; OR = 4; XOR = 5
    EQ = 6; NE = 7
    ULT = 8; ULE = 9; UGT = 10; UGE = 11
    SLT = 12; SLE = 13; SGT = 14; SGE = 15
    BOOL_AND = 16; BOOL_OR = 17; IMPLIES = 18


class SymExpr:
    """Owned handle to a Z3 expression produced by a SymbolicExecutor.

    Arithmetic and comparison operators build new expressions rather than
    computing anything, so ``==`` returns a SymExpr and not a bool — the same
    convention z3py uses::

        goal = exec.read_register(x86.RAX) == 0x1337
        solution = exec.solve(goal)

    Comparison operators are *signed*, matching Python's own semantics for
    integers. Use ult()/ule()/ugt()/uge() for the unsigned versions.
    """

    __hash__ = object.__hash__

    def __init__(self, ptr):
        self._ptr = ptr

    def _release(self):
        """Free the underlying Z3 expression. Idempotent."""
        if getattr(self, '_ptr', None):
            lib.dragon_symexpr_destroy(self._ptr)
            self._ptr = None

    def _handle(self):
        if not getattr(self, '_ptr', None):
            raise RuntimeError('this expression has already been released')
        return self._ptr

    def __del__(self):
        self._release()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._release()

    @property
    def width(self):
        """Bit width of a bitvector expression; 0 for a boolean."""
        return int(lib.dragon_symexpr_width(self._handle()))

    @property
    def is_bool(self):
        return bool(lib.dragon_symexpr_is_bool(self._handle()))

    def to_string(self):
        raw = lib.dragon_symexpr_to_string(self._handle())
        try:
            return ffi.string(raw).decode()
        finally:
            lib.dragon_cstr_free(raw)

    def to_smt2(self):
        """A complete SMT-LIB 2 script, declarations included, asserting
        ``(= |dragon!result| <this>)`` for a bitvector or the expression
        itself for a boolean. Another Z3 binding can parse it back into a term
        without being told what the free variables are; see to_z3()."""
        raw = lib.dragon_symexpr_to_smt2(self._handle())
        try:
            return ffi.string(raw).decode()
        finally:
            lib.dragon_cstr_free(raw)

    def to_z3(self, ctx=None):
        """This expression as a z3py term (needs the z3-solver package)."""
        import z3
        formula = z3.parse_smt2_string(self.to_smt2(), ctx=ctx)[0]
        if self.is_bool:
            return formula
        # `(= |dragon!result| e)`: take whichever side is not the marker.
        a, b = formula.arg(0), formula.arg(1)
        marker = z3.is_const(a) and a.decl().name() == 'dragon!result'
        return b if marker else a

    def as_int(self):
        """The value if the expression folds to a literal of at most 64 bits,
        else None. No solver involved - see SymbolicExecutor.evaluate for the
        'unique under the path constraints' question."""
        out = ffi.new('uint64_t*')
        if not lib.dragon_symexpr_as_u64(self._handle(), out):
            return None
        return int(out[0])

    def __str__(self):
        return self.to_string()

    def __repr__(self):
        return 'SymExpr(%s)' % self.to_string()

    def _coerce(self, other):
        """Turn a plain int operand into a bitvector of this expression's
        width, so `rax + 1` works."""
        if isinstance(other, SymExpr):
            return other, False
        if isinstance(other, int):
            if self._owner is None:
                raise TypeError('cannot build a constant without an executor')
            return self._owner.const(other, self.width), True
        raise TypeError('expected SymExpr or int, got %r' % type(other))

    def _binop(self, op, other):
        rhs, temporary = self._coerce(other)
        try:
            ptr = lib.dragon_symexpr_binop(op, self._handle(), rhs._handle())
        finally:
            if temporary:
                rhs._release()
        if ptr == ffi.NULL:
            raise ValueError('operand sorts do not fit this operator')
        return SymExpr._own(ptr, self._owner)

    # The executor that built this expression, so int operands can be widened
    # to a matching bitvector. Set by _own().
    _owner = None

    @staticmethod
    def _own(ptr, owner):
        e = SymExpr(ptr)
        e._owner = owner
        return e

    def __add__(self, o): return self._binop(_SymOp.ADD, o)
    def __sub__(self, o): return self._binop(_SymOp.SUB, o)
    def __mul__(self, o): return self._binop(_SymOp.MUL, o)
    def __and__(self, o): return self._binop(_SymOp.AND, o)
    def __or__(self, o): return self._binop(_SymOp.OR, o)
    def __xor__(self, o): return self._binop(_SymOp.XOR, o)
    def __radd__(self, o): return self._binop(_SymOp.ADD, o)
    def __rmul__(self, o): return self._binop(_SymOp.MUL, o)
    def __rand__(self, o): return self._binop(_SymOp.AND, o)
    def __ror__(self, o): return self._binop(_SymOp.OR, o)
    def __rxor__(self, o): return self._binop(_SymOp.XOR, o)

    def __eq__(self, o): return self._binop(_SymOp.EQ, o)
    def __ne__(self, o): return self._binop(_SymOp.NE, o)
    def __lt__(self, o): return self._binop(_SymOp.SLT, o)
    def __le__(self, o): return self._binop(_SymOp.SLE, o)
    def __gt__(self, o): return self._binop(_SymOp.SGT, o)
    def __ge__(self, o): return self._binop(_SymOp.SGE, o)

    def ult(self, o): return self._binop(_SymOp.ULT, o)
    def ule(self, o): return self._binop(_SymOp.ULE, o)
    def ugt(self, o): return self._binop(_SymOp.UGT, o)
    def uge(self, o): return self._binop(_SymOp.UGE, o)

    def logical_and(self, o): return self._binop(_SymOp.BOOL_AND, o)
    def logical_or(self, o): return self._binop(_SymOp.BOOL_OR, o)
    def implies(self, o): return self._binop(_SymOp.IMPLIES, o)

    def __invert__(self):
        """Boolean negation. Only valid on a boolean expression."""
        ptr = lib.dragon_symexpr_not(self._handle())
        if ptr == ffi.NULL:
            raise ValueError('~ is boolean negation; this expression is not a bool')
        return SymExpr._own(ptr, self._owner)

    def ite(self, yes, no):
        """Select between same-sort SymExpr arms using this boolean condition.

        All three expressions must belong to the same executor/context. No
        solver model is selected and no path assumptions are added.
        """
        if not isinstance(yes, SymExpr) or not isinstance(no, SymExpr):
            raise TypeError('ite arms must be SymExpr objects')
        ptr = lib.dragon_symexpr_ite(self._handle(), yes._handle(), no._handle())
        if ptr == ffi.NULL:
            raise ValueError('ite requires a bool condition, equal arm sorts and one context')
        return SymExpr._own(ptr, self._owner)


class Successor:
    """One address control flow can reach out of a block, and the condition
    under which it is reached."""

    def __init__(self, address, taken, condition):
        self.address = address
        self.taken = taken
        self.condition = condition

    def __repr__(self):
        return 'Successor(address=0x%x, taken=%s)' % (self.address, self.taken)


class SymWarning:
    """A soft problem that did not stop execution: an address too symbolic to
    resolve, an enumeration that hit its bound, a solver timeout."""

    def __init__(self, address, message):
        self.address = address
        self.message = message

    def __repr__(self):
        return 'SymWarning(0x%x: %s)' % (self.address, self.message)


class UnresolvedAccess:
    """A LOAD or STORE whose address had too many satisfying values to expand.

    The load produced a fresh variable and the store was dropped, each with a
    warning. `address` is the address expression; `value` is what was stored,
    or the variable standing in for what was loaded."""

    __slots__ = ('is_store', 'op_address', 'width', 'address', 'value')

    def __init__(self, is_store, op_address, width, address, value):
        self.is_store = is_store
        self.op_address = op_address
        self.width = width
        self.address = address
        self.value = value

    def __repr__(self):
        return '%s(i%d @0x%x)' % ('UnresolvedStore' if self.is_store
                                  else 'UnresolvedLoad', self.width, self.op_address)


class MemoryReadChoice:
    """Owned exact paused LOAD; restore its state before choosing another arm."""
    def __init__(self, ptr, owner):
        self._ptr, self._owner = ptr, owner
        self.expression = SymExpr._own(lib.dragon_read_choice_expression(ptr), owner)
        self.next_op = int(lib.dragon_read_choice_next_op(ptr))
        self.address = int(lib.dragon_read_choice_address(ptr))
        self.slot = int(lib.dragon_read_choice_slot(ptr))
        self.is_value = bool(lib.dragon_read_choice_is_value(ptr))
        count = int(lib.dragon_read_choice_count(ptr))
        self.values = [int(lib.dragon_read_choice_value(ptr, i)) for i in range(count)]
        self.guards = [SymExpr._own(lib.dragon_read_choice_guard(ptr, i), owner) for i in range(count)]

    def __del__(self):
        if getattr(self, '_ptr', None):
            lib.dragon_read_choice_destroy(self._ptr)
            self._ptr = None

    def choose(self, index):
        if not lib.dragon_symexec_choose_read(self._owner._handle(), self._ptr, index):
            raise ValueError('invalid read choice or executor')


class RunResult:
    """What one SymbolicExecutor.run() did."""

    def __init__(self, ptr, owner):
        self.status = int(lib.dragon_symrun_status(ptr))
        self.exit = int(lib.dragon_symrun_exit(ptr))
        self.complete = bool(lib.dragon_symrun_complete(ptr))
        choice = lib.dragon_symrun_read_choice(ptr)
        self.memory_choice = MemoryReadChoice(choice, owner) if choice != ffi.NULL else None

        raw = lib.dragon_symrun_error(ptr)
        if raw == ffi.NULL:
            self.error = None
        else:
            try:
                self.error = ffi.string(raw).decode()
            finally:
                lib.dragon_cstr_free(raw)

        ops = ffi.new('size_t*'); queries = ffi.new('size_t*'); conc = ffi.new('size_t*')
        lib.dragon_symrun_stats(ptr, ops, queries, conc)
        self.ops_executed = int(ops[0])
        self.solver_queries = int(queries[0])
        self.addresses_concretized = int(conc[0])

        self.timing_events = []
        taddr = ffi.new('uint64_t*'); tkind = ffi.new('uint32_t*')
        tsc = ffi.new('uint64_t*'); aux = ffi.new('uint32_t*')
        for i in range(int(lib.dragon_symrun_host_timestamp_count(ptr))):
            if lib.dragon_symrun_host_timestamp(ptr, i, taddr, tkind, tsc, aux):
                value = int(tsc[0])
                self.timing_events.append({
                    'address': int(taddr[0]),
                    'kind': 'rdtsc' if tkind[0] == 1 else 'rdtscp',
                    'tsc': value, 'eax': value & 0xffffffff, 'edx': value >> 32,
                    'aux': int(aux[0]) if tkind[0] == 2 else None,
                    'source': 'analysis-host CPU',
                })

        self.successors = []
        addr = ffi.new('uint64_t*'); taken = ffi.new('int*')
        for i in range(int(lib.dragon_symrun_successor_count(ptr))):
            if not lib.dragon_symrun_successor(ptr, i, addr, taken):
                continue
            cond = lib.dragon_symrun_successor_condition(ptr, i)
            self.successors.append(Successor(
                int(addr[0]), bool(taken[0]),
                SymExpr._own(cond, owner) if cond != ffi.NULL else None))

        self.unresolved = []
        is_store = ffi.new('int*'); op_addr = ffi.new('uint64_t*')
        width = ffi.new('uint8_t*')
        for i in range(int(lib.dragon_symrun_unresolved_count(ptr))):
            if not lib.dragon_symrun_unresolved(ptr, i, is_store, op_addr, width):
                continue
            self.unresolved.append(UnresolvedAccess(
                bool(is_store[0]), int(op_addr[0]), int(width[0]),
                SymExpr._own(lib.dragon_symrun_unresolved_address(ptr, i), owner),
                SymExpr._own(lib.dragon_symrun_unresolved_value(ptr, i), owner)))

        self.warnings = []
        for i in range(int(lib.dragon_symrun_warning_count(ptr))):
            waddr = ffi.new('uint64_t*')
            raw = lib.dragon_symrun_warning(ptr, i, waddr)
            if raw == ffi.NULL:
                continue
            try:
                self.warnings.append(SymWarning(int(waddr[0]),
                                                ffi.string(raw).decode()))
            finally:
                lib.dragon_cstr_free(raw)

    @property
    def ok(self):
        return self.status == SymExecStatus.OK

    @property
    def successor_addresses(self):
        return [s.address for s in self.successors]

    def __repr__(self):
        return 'RunResult(ok=%s, exit=%d, successors=%s, complete=%s)' % (
            self.ok, self.exit,
            ['0x%x' % s.address for s in self.successors], self.complete)


class Solution:
    """A satisfying assignment: every free variable the executor created,
    bound to a concrete value."""

    def __init__(self, ptr):
        self._ptr = ptr
        self._values = {}

        @ffi.callback('void(const char*, uint64_t, void*)')
        def collect(name, value, _user):
            self._values[ffi.string(name).decode()] = int(value)

        lib.dragon_solution_each(ptr, collect, ffi.NULL)

    def __del__(self):
        if getattr(self, '_ptr', None):
            lib.dragon_solution_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    def value(self, symbol):
        """Concrete value of one symbol, or None if the model does not bind it."""
        return self._values.get(symbol)

    def values(self):
        """Every bound symbol, as a name -> value dict."""
        return dict(self._values)

    def bytes(self, region):
        """Bytes of a symbolised memory region, in address order.
        Returns b'' if no region of that name was symbolised."""
        name = region.encode()
        size = int(lib.dragon_solution_bytes(self._ptr, name, ffi.NULL, 0))
        if size == 0:
            return b''
        buf = ffi.new('uint8_t[]', size)
        lib.dragon_solution_bytes(self._ptr, name, buf, size)
        return bytes(ffi.buffer(buf, size))

    def __repr__(self):
        return 'Solution(%d symbols)' % len(self._values)


class SymState:
    """Owned snapshot of an executor's register, memory and constraint state.

    Copying the state is much cheaper than rebuilding it, so an analysis that
    runs many blocks from the same seeded machine should seed once and rewind:

        exec = SymbolicExecutor()
        exec.symbolize_memory(0x4000, 16, 'input')
        exec.set_register(x86.RDI, 0x4000)
        seeded = exec.snapshot()

        for block in blocks:
            exec.restore(seeded)
            exec.run(block)

    The snapshot keeps its executor alive on its own, so it stays valid even
    if the executor goes out of scope first.
    """

    def __init__(self, ptr, owner):
        self._ptr = ptr
        self._owner = owner   # keeps the executor alive for our z3 handles

    def _release(self):
        """Free the snapshot. Idempotent."""
        if getattr(self, '_ptr', None):
            lib.dragon_symstate_destroy(self._ptr)
            self._ptr = None

    def __del__(self):
        self._release()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self._release()

    def _handle(self):
        if not getattr(self, '_ptr', None):
            raise RuntimeError('snapshot has been released')
        return self._ptr

    def join_guarded(self, incoming, condition):
        """At a native-block boundary select incoming on condition, self otherwise.

        Retains exact registers, memory bytes and guarded path constraints; no
        widening. Images must be shared and array effects/access observers off.
        Block-local temporaries are discarded. Returns a Boolean projection
        violation for an independent UNSAT check, not a path assumption.
        """
        ptr = lib.dragon_symstate_join_guarded(self._handle(), incoming._handle(),
                                              condition._handle())
        if ptr == ffi.NULL:
            raise RuntimeError('could not join those boundary states exactly')
        return SymExpr._own(ptr, self._owner)

    def merge(self, incoming, tag):
        """Join the snapshot `incoming` into this one: every register or memory
        byte the two disagree on becomes a fresh variable here, named after
        `tag`. Returns the symbolised locations as a list of StateDelta whose
        `value` is the new variable; an empty list means `incoming` added
        nothing - the fixed-point test of a worklist exploration::

            changed = entry_state[node].merge(exec.snapshot(), tag=node_name)
            if changed:
                worklist.append(node)

        Bytes an earlier merge under the same tag already symbolised are left
        alone, so merging into one snapshot repeatedly converges."""
        ptr = lib.dragon_symstate_merge(self._handle(), incoming._handle(),
                                        tag.encode())
        if ptr == ffi.NULL:
            raise RuntimeError('could not merge those snapshots')
        return _read_diff(ptr, self._owner)


class CallTrace:
    """Shared, nested all-read/all-write invocation footprint (not live-in liveness)."""
    def __init__(self, executor):
        self._owner = executor
        self._ptr = lib.dragon_symexec_begin_call_trace(executor._handle())
        if self._ptr == ffi.NULL:
            raise RuntimeError('could not begin call footprint')

    def detach(self):
        lib.dragon_symexec_detach_call_trace(self._owner._handle(), self._ptr)

    @property
    def cacheable(self):
        return bool(lib.dragon_call_trace_cacheable(self._ptr))

    def __del__(self):
        if getattr(self, '_ptr', None):
            lib.dragon_call_trace_destroy(self._ptr)
            self._ptr = None


class StateSummary:
    """Fixed-layout, deterministic physical-state transformer.

    Prove projection_violation and applicability_violation independently UNSAT
    before apply. No solver-model input selection or unstated purity assumptions.
    """
    def __init__(self, executor, before, after, trace, return_slot, tag, rewrites=()):
        self._owner = executor
        old = ffi.new('const dragon_symexpr_t*[]', [a._handle() for a, _ in rewrites])
        new = ffi.new('const dragon_symexpr_t*[]', [b._handle() for _, b in rewrites])
        error = ffi.new('char**')
        self._ptr = lib.dragon_state_summary_build(before._handle(), after._handle(),
            trace._ptr, return_slot, str(tag).encode(), old, new, len(rewrites), error)
        if self._ptr == ffi.NULL:
            message = ffi.string(error[0]).decode() if error[0] != ffi.NULL else 'state summary build failed'
            if error[0] != ffi.NULL:
                lib.dragon_cstr_free(error[0])
            raise ValueError(message)

    @property
    def projection_violation(self):
        return SymExpr._own(lib.dragon_state_summary_projection(self._ptr), self._owner)

    def applicability_violation(self):
        ptr = lib.dragon_state_summary_applicability(self._ptr, self._owner._handle())
        if ptr == ffi.NULL:
            raise ValueError('state summary layout/mode mismatch')
        return SymExpr._own(ptr, self._owner)

    def apply(self):
        if not lib.dragon_state_summary_apply(self._ptr, self._owner._handle()):
            raise RuntimeError('state summary application failed')

    @property
    def shape(self):
        return dict(input_ranges=int(lib.dragon_state_summary_input_count(self._ptr)),
                    output_ranges=int(lib.dragon_state_summary_output_count(self._ptr)))

    def __del__(self):
        if getattr(self, '_ptr', None):
            lib.dragon_state_summary_destroy(self._ptr)
            self._ptr = None


class StateDelta:
    """One location whose value differs between two states.

    `kind` is 'reg' or 'mem'. For a register, `key` is the IGNIL
    register-space byte offset (the first element of the descriptors in the
    x86 / arm classes); for memory it is the address. `width` is in bits, and
    `value` is the SymExpr the location holds now.
    """

    REGISTER = 0
    MEMORY = 1

    __slots__ = ('kind', 'key', 'width', 'value')

    def __init__(self, kind, key, width, value):
        self.kind = kind
        self.key = key
        self.width = width
        self.value = value

    @property
    def is_register(self):
        return self.kind == 'reg'

    def __repr__(self):
        where = f'reg[{self.key:#x}]' if self.is_register else f'mem[{self.key:#x}]'
        return f'StateDelta({where}:i{self.width} = {self.value})'


def _read_diff(ptr, owner):
    """Drain and free a dragon_symdiff_t into a list of StateDelta."""
    try:
        kind = ffi.new('int*')
        key = ffi.new('uint64_t*')
        width = ffi.new('uint8_t*')
        out = []
        for i in range(int(lib.dragon_symdiff_count(ptr))):
            if not lib.dragon_symdiff_entry(ptr, i, kind, key, width):
                continue
            value = SymExpr._own(lib.dragon_symdiff_value(ptr, i), owner)
            out.append(StateDelta(
                'reg' if kind[0] == StateDelta.REGISTER else 'mem',
                int(key[0]), int(width[0]), value))
        return out
    finally:
        lib.dragon_symdiff_destroy(ptr)


class SymbolicExecutor:
    """Symbolic execution of IGNIL blocks over Z3 bitvectors.

    Seed the machine, run a block, then ask the solver about what it computed::

        exec = SymbolicExecutor()
        exec.symbolize_memory(0x4000, 8, 'flag')
        exec.set_register(x86.RDI, 0x4000)
        result = exec.run(block)
        solution = exec.solve(exec.read_register(x86.RAX) == 0xdeadbeef)
        if solution:
            print(solution.bytes('flag'))

    Registers are the (offset, width, name) tuples from the x86 / arm classes.
    State persists across run() calls, so walking a path is a sequence of runs.

    Expressions may safely outlive the executor that produced them — each one
    keeps the underlying Z3 context alive on its own.

    Requires the library to have been built with -DDRAGON_USE_Z3=ON.
    """

    def __init__(self, solver_timeout_ms=0, max_address_solutions=0,
                 max_branch_targets=0, zero_extend_on_32bit_write=None,
                 symbolize_unmapped_reads=None, stop_at_terminator=None,
                 host_timestamps=None):
        """Every argument left at its default defers to the library default:
        a 5 s solver timeout, 64 candidate addresses per symbolic access, 256
        candidate branch targets, 32-bit register writes clearing the upper
        half, unmapped reads becoming fresh variables, and execution stopping
        at the first terminator (turn that off to run a lifted trace). Native
        host RDTSC/RDTSCP is on by default; host_timestamps=False retains
        symbolic timestamp results. Host samples are not source-time replay."""

        def tri(v):
            if v is None:
                return 0
            return 1 if v else -1

        opts = ffi.new('dragon_symexec_options_t*')
        opts.solver_timeout_ms = solver_timeout_ms
        opts.max_address_solutions = max_address_solutions
        opts.max_branch_targets = max_branch_targets
        opts.zero_extend_on_32bit_write = tri(zero_extend_on_32bit_write)
        opts.symbolize_unmapped_reads = tri(symbolize_unmapped_reads)
        opts.stop_at_terminator = tri(stop_at_terminator)

        self._ptr = lib.dragon_symexec_create(opts)
        if self._ptr == ffi.NULL:
            raise RuntimeError('could not create a symbolic executor')
        if host_timestamps is not None:
            self.set_host_timestamps(host_timestamps)

    def _handle(self):
        if not getattr(self, '_ptr', None):
            raise RuntimeError('this SymbolicExecutor has been destroyed')
        return self._ptr

    def __del__(self):
        # Only drops this object's reference. An expression still alive holds
        # one of its own (see the C shim's SymExecHandle), so the underlying
        # Z3 context outlives any expression built from it no matter which
        # order Python happens to finalize them in.
        if getattr(self, '_ptr', None):
            lib.dragon_symexec_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    def reset(self):
        """Drop all register, memory and constraint state; keep the options."""
        lib.dragon_symexec_reset(self._handle())

    def enable_memory_effects(self):
        """Track ALL executed IGNIL LOAD/STORE operations in one byte array.

        Call before running a path. The initial array is unconstrained: mapped
        capture bytes / concrete read_memory and write_memory setup are separate
        and are NOT imported into this mode. No independent objects or noalias
        assumption. Use effect_memory() for symbolic array inspection. Snapshots
        include array versions and event order; reset disables the mode again.
        """
        if not lib.dragon_symexec_enable_memory_effects(self._handle()):
            raise ValueError('memory-effect mode is already enabled')

    @property
    def memory_effects(self):
        """Ordered event dictionaries; load `value` is a fresh runtime token."""
        out = []
        for i in range(lib.dragon_symexec_memory_effect_count(self._handle())):
            store, pc, width = ffi.new('int*'), ffi.new('uint64_t*'), ffi.new('unsigned*')
            if not lib.dragon_symexec_memory_effect(self._handle(), i, store, pc, width):
                raise RuntimeError('memory-effect history changed while reading')
            out.append(dict(is_store=bool(store[0]), address_pc=int(pc[0]), width=int(width[0]),
                address=SymExpr._own(lib.dragon_symexec_memory_effect_address(self._handle(), i), self),
                value=SymExpr._own(lib.dragon_symexec_memory_effect_value(self._handle(), i), self)))
        return out

    def effect_memory(self, *, initial=False):
        """Current or initial BV64 -> BV8 array, including overlapping stores."""
        ptr = lib.dragon_symexec_effect_memory(self._handle(), int(initial))
        if ptr == ffi.NULL:
            raise ValueError('memory-effect mode is not enabled')
        return SymExpr._own(ptr, self)

    def effect_constraints(self):
        """Load-token equalities against the array version at each load."""
        ptr = lib.dragon_symexec_effect_constraints(self._handle())
        if ptr == ffi.NULL:
            raise ValueError('memory-effect mode is not enabled')
        return SymExpr._own(ptr, self)

    # -- snapshots and diffing -------------------------------------------------

    def begin_access_trace(self, ranges):
        """Watch (kind, key, byte_count) ranges through aliases and overlaps.

        kind is 'reg' or 'mem'; empty ranges watch all accessed bytes.
        Only execution between begin/end contributes;
        end disables the shared observer in all derived snapshots as well.
        """
        ranges = list(ranges)
        rows = [(0 if kind == 'reg' else 1, int(key), int(size))
                for kind, key, size in ranges]
        if any(kind not in ('reg', 'mem') for kind, _, _ in ranges):
            raise ValueError('state range kind must be reg or mem')
        data = ffi.new('dragon_state_range_t[]', rows) if rows else ffi.NULL
        if not lib.dragon_symexec_begin_access_trace(self._handle(), data, len(rows)):
            raise ValueError('invalid watched state ranges')

    def end_access_trace(self):
        """Return watched byte records with live_in/read/written flags."""
        result = []
        @ffi.callback('void(uint32_t, uint64_t, uint32_t, void*)')
        def collect(kind, key, flags, _):
            result.append(dict(kind='reg' if kind == 0 else 'mem', key=int(key),
                               live_in=bool(flags & 1), read=bool(flags & 2),
                               written=bool(flags & 4)))
        if not lib.dragon_symexec_end_access_trace(self._handle(), collect, ffi.NULL):
            raise RuntimeError('access trace capacity exceeded; liveness is incomplete')
        return result

    def symbolize_range(self, kind, key, width, name):
        """Bind one analysis-time physical range without GPR zero-extension.

        This does not alter how subsequent 32-bit machine writes behave.
        """
        if kind not in ('reg', 'mem'):
            raise ValueError('state range kind must be reg or mem')
        ptr = lib.dragon_symexec_symbolize_range(self._handle(), kind == 'mem',
                                                int(key), int(width), name.encode())
        if ptr == ffi.NULL:
            raise ValueError('invalid state range binding')
        return SymExpr._own(ptr, self)

    def snapshot(self):
        """Copy the current register, memory and constraint state.

        Pair with restore() to run many blocks from one seeded machine instead
        of building a fresh executor per block."""
        ptr = lib.dragon_symexec_snapshot(self._handle())
        if ptr == ffi.NULL:
            raise RuntimeError('could not snapshot the executor state')
        return SymState(ptr, self)

    def restore(self, state):
        """Replace the state wholesale with a snapshot taken from this
        executor."""
        lib.dragon_symexec_restore(self._handle(), state._handle())

    def diff(self, before):
        """Every register and memory location whose value differs from the
        snapshot `before`, as a list of StateDelta.

        This is the batch form of reading every candidate location back and
        comparing it to what it held: one call plus one expression per location
        that actually changed, rather than a read_register/read_memory per
        location. Runs of bytes that came from a single written value are
        reported as that one value, so a 64-bit store is one 64-bit delta and
        not eight byte-sized ones::

            seeded = exec.snapshot()
            exec.run(block)
            for d in exec.diff(seeded):
                print(d.kind, hex(d.key), d.width, d.value)
        """
        ptr = lib.dragon_symexec_diff(self._handle(), before._handle())
        if ptr == ffi.NULL:
            raise RuntimeError('could not diff against that snapshot')
        return _read_diff(ptr, self)

    # -- machine setup ---------------------------------------------------------

    @staticmethod
    def _reg(reg):
        """Accept an (offset, width, name) descriptor or a bare
        (offset, width) pair."""
        return int(reg[0]), int(reg[1])

    def set_register(self, reg, value):
        """Give a register a concrete value."""
        offset, width = self._reg(reg)
        lib.dragon_symexec_set_register(self._handle(), offset, width, value)

    def symbolize_register(self, reg, name=None):
        """Bind a register to a fresh free variable and return it."""
        offset, width = self._reg(reg)
        ptr = lib.dragon_symexec_symbolize_register(
            self._handle(), offset, width,
            name.encode() if name else ffi.NULL)
        return SymExpr._own(ptr, self)

    def bind_register_value(self, reg, name):
        """Name a computed value and its copies with a fresh exact equation.

        All original constraints and machine effects remain. No execution is
        skipped. The name must be fresh in the current snapshot.
        """
        offset, width = self._reg(reg)
        ptr = lib.dragon_symexec_bind_register_value(
            self._handle(), offset, width, name.encode())
        if ptr == ffi.NULL:
            raise ValueError('register value binding requires a fresh name and ordinary memory')
        return SymExpr._own(ptr, self)

    def map_memory(self, address, data):
        """Map a concrete blob — a lookup table, a constant pool, a captured
        stack frame."""
        buf = bytes(data)
        lib.dragon_symexec_map_memory(self._handle(), address, buf, len(buf))

    def symbolize_memory(self, address, size, name):
        """Fill [address, address+size) with per-byte free variables named
        `name[0]`..`name[size-1]`. Solution.bytes(name) reads them back."""
        ptr = lib.dragon_symexec_symbolize_memory(
            self._handle(), address, size, name.encode())
        if ptr == ffi.NULL:
            raise ValueError('could not symbolize that memory region')
        return SymExpr._own(ptr, self)

    def assume(self, condition):
        """Constrain the rest of the run — a precondition on an input, or a
        fact recovered from a trace."""
        lib.dragon_symexec_assume(self._handle(), condition._handle())

    def parse_condition(self, script):
        """Import the conjunction of SMT-LIB assertions, without assuming it.

        Input names and sorts identify existing symbols in this executor's
        context. No z3py/private context pointers cross the library boundary.
        """
        if not isinstance(script, str):
            raise TypeError('expected an SMT-LIB script string')
        ptr = lib.dragon_symexec_parse_condition(self._handle(), script.encode())
        if ptr == ffi.NULL:
            raise ValueError('invalid SMT-LIB condition')
        return SymExpr._own(ptr, self)

    def parse_expression(self, script):
        """Import one serialized BV DAG, without assumptions or state writes.

        The script must assert exactly (= |dragon!result| expression), as emitted
        by SymExpr.to_smt2(). Marker recursion and extra assertions are rejected.
        """
        if not isinstance(script, str):
            raise TypeError('expected an SMT-LIB expression script')
        ptr = lib.dragon_symexec_parse_expression(self._handle(), script.encode())
        if ptr == ffi.NULL:
            raise ValueError('invalid SMT-LIB expression envelope')
        return SymExpr._own(ptr, self)

    def simplify_projection(self, expression, domain, inputs=(), *, timeout_ms=2000):
        """Proof-only guard/data simplification, valid under explicit domain.

        Returns (expression, statistics). Does not assume domain, rewrite state,
        select model values for data, or globally bit-split symbolic words.
        """
        inputs = list(inputs)
        array = ffi.new('const dragon_symexpr_t*[]', [v._handle() for v in inputs]) if inputs else ffi.NULL
        queries, rewrites = ffi.new('size_t *'), ffi.new('size_t *')
        ptr = lib.dragon_symexec_simplify_projection(self._handle(), expression._handle(),
            domain._handle(), array, len(inputs), timeout_ms, queries, rewrites)
        if ptr == ffi.NULL:
            raise ValueError('invalid projection expression/domain/inputs')
        return SymExpr._own(ptr, self), dict(queries=int(queries[0]), rewrites=int(rewrites[0]))

    def specialize_equality(self, equality):
        """Rewrite state only if its retained constraints imply the equality.

        Returns True if rewritten, False if not implied, None on unknown or
        invalid input. Does not assume the equality or rewrite the path guard.
        """
        answer = lib.dragon_symexec_specialize_equality(self._handle(), equality._handle())
        return None if answer < 0 else bool(answer)

    def write_register(self, reg, expr):
        """Give a register an expression rather than a host integer."""
        offset, width = self._reg(reg)
        lib.dragon_symexec_write_register(self._handle(), offset, width,
                                          expr._handle())

    def write_memory(self, address, expr):
        """Store an expression little-endian at `address`, as many bytes as
        it is wide."""
        lib.dragon_symexec_write_memory(self._handle(), address, expr._handle())

    def set_fresh_tag(self, tag):
        """Context suffix for unresolved-load and UNDEF variables.

        They are named after the op's address and position in the run (UNDEF
        also includes destination and width), so
        running one block in two contexts hands out the same names - and two
        loads that may read different memory become one variable. Set a tag per
        context to keep them apart; '' restores the untagged names."""
        lib.dragon_symexec_set_fresh_tag(self._handle(), (tag or '').encode())

    # OPAQUE kinds, matching dragon::ignil::OpaqueKind.
    OPAQUE_CPUID = 0
    OPAQUE_RDTSC = 1
    OPAQUE_RDTSCP = 2

    def set_concrete_opaque(self, kind, selector, results):
        """Make an OPAQUE op return concrete `results` (a list of ints) instead
        of a symbol, so a concolic trace stays concrete through an anti-tamper
        CPUID. `kind` is one of OPAQUE_*; `selector` identifies the invocation
        from its operands (for CPUID use set_concrete_cpuid)."""
        buf = ffi.new('uint64_t[]', [int(v) & 0xFFFFFFFFFFFFFFFF for v in results])
        lib.dragon_symexec_set_concrete_opaque(self._handle(), int(kind),
                                               int(selector) & 0xFFFFFFFFFFFFFFFF,
                                               buf, len(results))

    def set_host_timestamps(self, enabled):
        """Enable native host timestamp observations, or retain symbolic ones."""
        lib.dragon_symexec_set_host_timestamps(self._handle(), int(bool(enabled)))

    @property
    def host_timestamps(self):
        return bool(lib.dragon_symexec_host_timestamps(self._handle()))

    def set_concrete_cpuid(self, leaf, sub, eax, ebx, ecx, edx):
        """Make CPUID(leaf, sub) return the given EAX/EBX/ECX/EDX as literals,
        so the VM's anti-tamper CPUID never turns the dispatch key symbolic."""
        selector = ((int(leaf) & 0xFFFFFFFF) << 32) | (int(sub) & 0xFFFFFFFF)
        self.set_concrete_opaque(self.OPAQUE_CPUID, selector, [eax, ebx, ecx, edx])

    def concrete_register(self, reg):
        """The register's value if it is a literal, else None. The cheap form
        of evaluate(read_register(reg)) for a register expected to be
        concrete: no expression handle and no solver."""
        offset, width = self._reg(reg)
        out = ffi.new('uint64_t*')
        if not lib.dragon_symexec_concrete_register(self._handle(), offset,
                                                    width, out):
            return None
        return int(out[0])

    def concrete_memory(self, address, width):
        """`width` bits at `address` if they are a literal, else None."""
        out = ffi.new('uint64_t*')
        if not lib.dragon_symexec_concrete_memory(self._handle(), address,
                                                  width, out):
            return None
        return int(out[0])

    # -- expressions -----------------------------------------------------------

    def const(self, value, width):
        """A concrete bitvector."""
        ptr = lib.dragon_symexec_const(self._handle(), value, width)
        if ptr == ffi.NULL:
            raise ValueError('width must be between 1 and 64')
        return SymExpr._own(ptr, self)

    def read_register(self, reg):
        """The expression a register currently holds."""
        offset, width = self._reg(reg)
        return SymExpr._own(
            lib.dragon_symexec_read_register(self._handle(), offset, width), self)

    def begin_call_trace(self):
        return CallTrace(self)

    def read_control_memory(self, address, width):
        """RET target read: preserve loop observers, distinguish invocation control input."""
        return SymExpr._own(lib.dragon_symexec_read_control_memory(self._handle(), address, width), self)

    def read_memory(self, address, width):
        """The expression `width` bits at `address` currently hold."""
        return SymExpr._own(
            lib.dragon_symexec_read_memory(self._handle(), address, width), self)

    # -- execution -------------------------------------------------------------

    def set_fork_reads(self, enabled=True):
        lib.dragon_symexec_set_fork_reads(self._handle(), bool(enabled))

    def run(self, block, *, first_op=0):
        """Execute an IGNIL block, optionally resuming at an exact op index."""
        ptr = (lib.dragon_symexec_run(self._handle(), block._ptr) if first_op == 0 else
               lib.dragon_symexec_run_from(self._handle(), block._ptr, first_op))
        if ptr == ffi.NULL:
            raise ValueError('could not run that block')
        try:
            return RunResult(ptr, self)
        finally:
            lib.dragon_symrun_destroy(ptr)

    # -- solver queries --------------------------------------------------------

    def is_satisfiable(self, condition):
        """True/False, or None if the solver timed out — never a guess."""
        r = int(lib.dragon_symexec_is_satisfiable(self._handle(), condition._handle()))
        return None if r < 0 else bool(r)

    def proves(self, condition):
        """Does the condition hold on every model of the path constraints?
        None if the solver timed out."""
        r = int(lib.dragon_symexec_proves(self._handle(), condition._handle()))
        return None if r < 0 else bool(r)

    def evaluate(self, expr):
        """The value of an expression if the path constraints force exactly
        one, else None — the 'is this obfuscated expression really a
        constant?' query."""
        out = ffi.new('uint64_t*')
        if not lib.dragon_symexec_evaluate(self._handle(), expr._handle(), out):
            return None
        return int(out[0])

    def enumerate(self, expr, max_solutions=64):
        """Up to `max_solutions` distinct satisfying values of an expression.

        Returns (values, exhaustive); `exhaustive` is True only when the
        enumeration ran out of values rather than hitting the bound, i.e. the
        list is the complete set."""
        buf = ffi.new('uint64_t[]', max_solutions)
        exhaustive = ffi.new('int*')
        n = int(lib.dragon_symexec_enumerate(
            self._handle(), expr._handle(), buf, max_solutions, exhaustive))
        return [int(buf[i]) for i in range(n)], bool(exhaustive[0])

    def solve(self, goal=None):
        """Solve the path constraints, plus `goal` if given. Returns a
        Solution, or None if there is no satisfying assignment."""
        ptr = lib.dragon_symexec_solve(
            self._handle(), goal._handle() if goal is not None else ffi.NULL)
        if ptr == ffi.NULL:
            return None
        return Solution(ptr)


# -- Loader --------------------------------------------------------------------

class Format:
    """Container format a LoadedImage was parsed from."""
    UNKNOWN = 0
    ELF = 1
    PE = 2


class SymbolKind:
    """What a loader Symbol names."""
    UNKNOWN = 0
    FUNCTION = 1
    OBJECT = 2
    SECTION = 3
    FILE = 4


class Section:
    """A section of a LoadedImage, placed at its virtual address."""

    def __init__(self, name, address, virtual_size, readable, writable,
                 executable, data):
        self.name = name
        self.address = address
        self.virtual_size = virtual_size
        self.readable = readable
        self.writable = writable
        self.executable = executable
        self.data = data  # bytes actually present in the file

    def __repr__(self):
        perms = ''.join(c if f else '-' for c, f in
                        zip('rwx', (self.readable, self.writable, self.executable)))
        return (f'<Section {self.name!r} @0x{self.address:x} '
                f'size=0x{self.virtual_size:x} {perms}>')


class Symbol:
    """A symbol-table entry of a LoadedImage."""

    def __init__(self, name, address, size, kind, imported, exported):
        self.name = name
        self.address = address
        self.size = size
        self.kind = kind
        self.imported = imported
        self.exported = exported

    def __repr__(self):
        return (f'<Symbol {self.name!r} @0x{self.address:x} '
                f'kind={self.kind} imported={self.imported} exported={self.exported}>')


class LoadedImage:
    """An ELF or PE image parsed from a file or bytes.

    Use the classmethods to construct::

        img = dragon.LoadedImage.load_file('a.out')
        print(hex(img.entry), img.architecture)
        graph = img.disassemble()
    """

    def __init__(self, ptr):
        self._ptr = ptr

    @classmethod
    def load_file(cls, path):
        """Load an ELF/PE image from a path. Raises ValueError on failure."""
        err = ffi.new('char[256]')
        ptr = lib.dragon_load_file(path.encode(), err, 256)
        if ptr == ffi.NULL:
            raise ValueError(ffi.string(err).decode() or 'failed to load image')
        return cls(ptr)

    @classmethod
    def load_bytes(cls, data):
        """Load an ELF/PE image from a bytes object. Raises ValueError on failure."""
        err = ffi.new('char[256]')
        ptr = lib.dragon_load_bytes(data, len(data), err, 256)
        if ptr == ffi.NULL:
            raise ValueError(ffi.string(err).decode() or 'failed to load image')
        return cls(ptr)

    def __del__(self):
        if self._ptr:
            lib.dragon_loader_destroy(self._ptr)
            self._ptr = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.__del__()

    @property
    def format(self):
        return lib.dragon_loader_format(self._ptr)

    @property
    def architecture(self):
        return lib.dragon_loader_architecture(self._ptr)

    @property
    def is_64bit(self):
        return bool(lib.dragon_loader_is_64bit(self._ptr))

    @property
    def image_base(self):
        return lib.dragon_loader_image_base(self._ptr)

    @property
    def entry(self):
        """Entry-point virtual address, or None if the image has none."""
        if not lib.dragon_loader_has_entry(self._ptr):
            return None
        return lib.dragon_loader_entry(self._ptr)

    def _regions(self, count, describe, raw_bytes):
        out = []
        for i in range(count(self._ptr)):
            addr = ffi.new('uint64_t*')
            vsize = ffi.new('uint64_t*')
            r = ffi.new('int*'); w = ffi.new('int*'); x = ffi.new('int*')
            name = describe(self._ptr, i, addr, vsize, r, w, x)
            length = ffi.new('size_t*')
            data_ptr = raw_bytes(self._ptr, i, length)
            data = (ffi.buffer(data_ptr, length[0])[:] if data_ptr != ffi.NULL
                    else b'')
            out.append(Section(ffi.string(name).decode(), addr[0], vsize[0],
                               bool(r[0]), bool(w[0]), bool(x[0]), data))
        return out

    def sections(self):
        return self._regions(lib.dragon_loader_section_count,
                             lib.dragon_loader_section,
                             lib.dragon_loader_section_bytes)

    def segments(self):
        """ELF PT_LOAD segments as Sections named "LOAD0", "LOAD1", ... - what
        the system loader maps, and the only layout left when a protector
        strips the section headers. Empty for PE."""
        return self._regions(lib.dragon_loader_segment_count,
                             lib.dragon_loader_segment,
                             lib.dragon_loader_segment_bytes)

    def symbols(self):
        out = []
        for i in range(lib.dragon_loader_symbol_count(self._ptr)):
            addr = ffi.new('uint64_t*')
            size = ffi.new('uint64_t*')
            kind = ffi.new('dragon_symbol_kind_t*')
            imp = ffi.new('int*'); exp = ffi.new('int*')
            name = lib.dragon_loader_symbol(self._ptr, i, addr, size, kind, imp, exp)
            out.append(Symbol(ffi.string(name).decode(), addr[0], size[0],
                              int(kind[0]), bool(imp[0]), bool(exp[0])))
        return out

    def read_virtual(self, address, size):
        """Read `size` bytes from the virtual address space, or None if the
        range is not mapped."""
        buf = ffi.new('uint8_t[]', size)
        n = lib.dragon_loader_read_virtual(self._ptr, address, buf, size)
        if n == 0:
            return None
        return ffi.buffer(buf, n)[:]

    def disassemble(self, config=None):
        """Disassemble every executable section into a populated Graph built
        for the image's detected architecture."""
        ptr = lib.dragon_loader_disassemble(
            self._ptr, config._ptr if config is not None else ffi.NULL)
        return Graph(ptr)

    def __repr__(self):
        fmt = {Format.ELF: 'ELF', Format.PE: 'PE'}.get(self.format, 'unknown')
        return f'<LoadedImage {fmt} arch={self.architecture} entry={self.entry}>'
