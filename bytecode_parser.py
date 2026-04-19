"""
bytecode_parser.py
Parser de bytecode Lua 5.1 (formato binário .luac).
Lê o header, funções, constantes, instruções e informações de debug.
"""

import struct
from dataclasses import dataclass, field


# ──────────────────────────────────────────────
#  Opcodes Lua 5.1 — tabela de mnemônicos
# ──────────────────────────────────────────────
OPCODES_51 = {
    0:  ("MOVE",      "AB",   "R(A) := R(B)"),
    1:  ("LOADK",     "ABx",  "R(A) := Kst(Bx)"),
    2:  ("LOADBOOL",  "ABC",  "R(A) := (Bool)B; if C then PC++"),
    3:  ("LOADNIL",   "AB",   "R(A)..R(B) := nil"),
    4:  ("GETUPVAL",  "AB",   "R(A) := UpValue[B]"),
    5:  ("GETGLOBAL", "ABx",  "R(A) := Gbl[Kst(Bx)]"),
    6:  ("GETTABLE",  "ABC",  "R(A) := R(B)[RK(C)]"),
    7:  ("SETGLOBAL", "ABx",  "Gbl[Kst(Bx)] := R(A)"),
    8:  ("SETUPVAL",  "AB",   "UpValue[B] := R(A)"),
    9:  ("SETTABLE",  "ABC",  "R(A)[RK(B)] := RK(C)"),
    10: ("NEWTABLE",  "ABC",  "R(A) := {} (array B, hash C)"),
    11: ("SELF",      "ABC",  "R(A+1) := R(B); R(A) := R(B)[RK(C)]"),
    12: ("ADD",       "ABC",  "R(A) := RK(B) + RK(C)"),
    13: ("SUB",       "ABC",  "R(A) := RK(B) - RK(C)"),
    14: ("MUL",       "ABC",  "R(A) := RK(B) * RK(C)"),
    15: ("DIV",       "ABC",  "R(A) := RK(B) / RK(C)"),
    16: ("MOD",       "ABC",  "R(A) := RK(B) % RK(C)"),
    17: ("POW",       "ABC",  "R(A) := RK(B) ^ RK(C)"),
    18: ("UNM",       "AB",   "R(A) := -R(B)"),
    19: ("NOT",       "AB",   "R(A) := not R(B)"),
    20: ("LEN",       "AB",   "R(A) := length of R(B)"),
    21: ("CONCAT",    "ABC",  "R(A) := R(B)..R(C)"),
    22: ("JMP",       "sBx",  "PC += sBx"),
    23: ("EQ",        "ABC",  "if (RK(B) == RK(C)) ~= A then PC++"),
    24: ("LT",        "ABC",  "if (RK(B) <  RK(C)) ~= A then PC++"),
    25: ("LE",        "ABC",  "if (RK(B) <= RK(C)) ~= A then PC++"),
    26: ("TEST",      "AC",   "if not (R(A) <=> C) then PC++"),
    27: ("TESTSET",   "ABC",  "if (R(B) <=> C) then R(A):=R(B) else PC++"),
    28: ("CALL",      "ABC",  "R(A)..R(A+C-2) := R(A)(R(A+1)..R(A+B-1))"),
    29: ("TAILCALL",  "AB",   "return R(A)(R(A+1)..R(A+B-1))"),
    30: ("RETURN",    "AB",   "return R(A)..R(A+B-2)"),
    31: ("FORLOOP",   "AsBx", "R(A) += R(A+2); if R(A) <?= R(A+1) then {PC+=sBx; R(A+3)=R(A)}"),
    32: ("FORPREP",   "AsBx", "R(A) -= R(A+2); PC+=sBx"),
    33: ("TFORLOOP",  "AC",   "R(A+3)..R(A+2+C) := R(A)(R(A+1), R(A+2))"),
    34: ("SETLIST",   "ABC",  "R(A)[Bx*FPF+i] := R(A+i) for 1<=i<=C"),
    35: ("CLOSE",     "A",    "close upvalues >= R(A)"),
    36: ("CLOSURE",   "ABx",  "R(A) := closure(Proto[Bx], R(A)..R(A+n))"),
    37: ("VARARG",    "AB",   "R(A)..R(A+B-2) = vararg"),
}

# Tipos de constantes Lua 5.1
LUA_TNIL     = 0
LUA_TBOOLEAN = 1
LUA_TNUMBER  = 3
LUA_TSTRING  = 4

MAXARG_BX  = 0x3FFFF   # 18 bits
MAXARG_SBX = MAXARG_BX >> 1


@dataclass
class Instruction:
    opcode: int
    name: str
    mode: str
    A: int = 0
    B: int = 0
    C: int = 0
    Bx: int = 0
    sBx: int = 0
    raw: int = 0
    line: int = 0

    def __str__(self):
        info = OPCODES_51.get(self.opcode, (f"OP_{self.opcode}", "", ""))
        desc = info[2] if len(info) > 2 else ""
        mode = self.mode
        if mode in ("ABx", "AsBx"):
            return f"[{self.line:4d}] {self.name:<12} A={self.A:<3} Bx={self.Bx:<6}  ; {desc}"
        return f"[{self.line:4d}] {self.name:<12} A={self.A:<3} B={self.B:<4} C={self.C:<4}  ; {desc}"


@dataclass
class LuaFunction:
    source_name: str = ""
    line_defined: int = 0
    last_line_defined: int = 0
    num_upvalues: int = 0
    num_params: int = 0
    is_vararg: int = 0
    max_stack: int = 0
    instructions: list = field(default_factory=list)
    constants: list = field(default_factory=list)
    functions: list = field(default_factory=list)
    source_lines: list = field(default_factory=list)
    locals: list = field(default_factory=list)
    upvalue_names: list = field(default_factory=list)


class BytecodeParser:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.little_endian = True
        self.int_size = 4
        self.size_t_size = 4
        self.number_size = 8
        self.number_integral = False

    # ── Leitores primitivos ──────────────────────

    def read_bytes(self, n: int) -> bytes:
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def read_byte(self) -> int:
        b = self.data[self.pos]
        self.pos += 1
        return b

    def read_int(self) -> int:
        fmt = "<i" if self.little_endian else ">i"
        v = struct.unpack_from(fmt, self.data, self.pos)[0]
        self.pos += self.int_size
        return v

    def read_uint(self) -> int:
        fmt = "<I" if self.little_endian else ">I"
        v = struct.unpack_from(fmt, self.data, self.pos)[0]
        self.pos += self.int_size
        return v

    def read_size_t(self) -> int:
        if self.size_t_size == 4:
            fmt = "<I" if self.little_endian else ">I"
        else:
            fmt = "<Q" if self.little_endian else ">Q"
        v = struct.unpack_from(fmt, self.data, self.pos)[0]
        self.pos += self.size_t_size
        return v

    def read_number(self) -> float:
        if self.number_integral:
            fmt = "<q" if self.little_endian else ">q"
            v = struct.unpack_from(fmt, self.data, self.pos)[0]
        else:
            fmt = "<d" if self.little_endian else ">d"
            v = struct.unpack_from(fmt, self.data, self.pos)[0]
        self.pos += self.number_size
        return v

    def read_string(self) -> str | None:
        size = self.read_size_t()
        if size == 0:
            return None
        s = self.data[self.pos:self.pos + size - 1]  # sem \0
        self.pos += size
        try:
            return s.decode("utf-8")
        except UnicodeDecodeError:
            return s.decode("latin-1")

    # ── Header ──────────────────────────────────

    def parse_header(self) -> dict:
        sig = self.read_bytes(4)
        if sig != b"\x1bLua":
            raise ValueError(f"Assinatura inválida: {sig!r}")

        version = self.read_byte()
        if version not in (0x51, 0x52):
            raise ValueError(f"Versão Lua não suportada: {version:#x}")

        fmt = self.read_byte()          # formato (0 = oficial)
        endian = self.read_byte()       # 1 = little
        self.little_endian = endian == 1
        self.int_size = self.read_byte()
        self.size_t_size = self.read_byte()
        instr_size = self.read_byte()   # tamanho da instrução (sempre 4)
        self.number_size = self.read_byte()
        self.number_integral = self.read_byte() == 1

        return {
            "version": f"5.{version & 0xF}",
            "format": fmt,
            "little_endian": self.little_endian,
            "int_size": self.int_size,
            "size_t_size": self.size_t_size,
            "number_size": self.number_size,
            "number_integral": self.number_integral,
        }

    # ── Instrução ────────────────────────────────

    def _decode_instruction(self, raw: int) -> Instruction:
        opcode = raw & 0x3F
        A  = (raw >> 6)  & 0xFF
        C  = (raw >> 14) & 0x1FF
        B  = (raw >> 23) & 0x1FF
        Bx = (raw >> 14) & 0x3FFFF
        sBx = Bx - MAXARG_SBX

        info = OPCODES_51.get(opcode, (f"OP_{opcode}", "ABC", "?"))
        return Instruction(
            opcode=opcode,
            name=info[0],
            mode=info[1],
            A=A, B=B, C=C, Bx=Bx, sBx=sBx,
            raw=raw,
        )

    # ── Função ──────────────────────────────────

    def parse_function(self) -> LuaFunction:
        fn = LuaFunction()
        fn.source_name      = self.read_string() or "?"
        fn.line_defined     = self.read_int()
        fn.last_line_defined= self.read_int()
        fn.num_upvalues     = self.read_byte()
        fn.num_params       = self.read_byte()
        fn.is_vararg        = self.read_byte()
        fn.max_stack        = self.read_byte()

        # Instruções
        n_inst = self.read_int()
        for _ in range(n_inst):
            raw = self.read_uint()
            fn.instructions.append(self._decode_instruction(raw))

        # Constantes
        n_const = self.read_int()
        for _ in range(n_const):
            t = self.read_byte()
            if t == LUA_TNIL:
                fn.constants.append(None)
            elif t == LUA_TBOOLEAN:
                fn.constants.append(bool(self.read_byte()))
            elif t == LUA_TNUMBER:
                fn.constants.append(self.read_number())
            elif t == LUA_TSTRING:
                fn.constants.append(self.read_string())
            else:
                fn.constants.append(f"<type {t}>")

        # Sub-funções
        n_func = self.read_int()
        for _ in range(n_func):
            fn.functions.append(self.parse_function())

        # Info de debug
        n_lines = self.read_int()
        for i in range(n_lines):
            ln = self.read_int()
            if i < len(fn.instructions):
                fn.instructions[i].line = ln
            fn.source_lines.append(ln)

        n_locals = self.read_int()
        for _ in range(n_locals):
            name = self.read_string() or "_"
            start_pc = self.read_int()
            end_pc   = self.read_int()
            fn.locals.append((name, start_pc, end_pc))

        n_upvals = self.read_int()
        for _ in range(n_upvals):
            fn.upvalue_names.append(self.read_string() or "_upval")

        return fn

    # ── Entry point ─────────────────────────────

    def parse(self) -> tuple[dict, LuaFunction]:
        header = self.parse_header()
        main   = self.parse_function()
        return header, main
