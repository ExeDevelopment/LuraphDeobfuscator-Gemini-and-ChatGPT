"""
reconstructor.py
Reconstrói código Lua legível a partir do bytecode parseado.
Faz análise de fluxo básica para recuperar estruturas de controle.
"""

from bytecode_parser import LuaFunction, Instruction, OPCODES_51


INDENT = "    "


def _fmt_const(val, idx: int) -> str:
    """Formata uma constante Lua para exibição no código."""
    if val is None:
        return "nil"
    if isinstance(val, bool):
        return "true" if val else "false"
    if isinstance(val, float):
        if val == int(val):
            return str(int(val))
        return repr(val)
    if isinstance(val, str):
        escaped = val.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r")
        return f'"{escaped}"'
    return f"K[{idx}]"


def _rk(idx: int, constants: list) -> str:
    """Resolve RK(x): se bit 8 setado é constante, senão registrador."""
    if idx & 256:
        cidx = idx & 0xFF
        if cidx < len(constants):
            return _fmt_const(constants[cidx], cidx)
        return f"K[{cidx}]"
    return f"r{idx}"


def _reg(idx: int) -> str:
    return f"r{idx}"


class FunctionReconstructor:
    """Converte uma LuaFunction em código Lua legível linha a linha."""

    def __init__(self, fn: LuaFunction, depth: int = 0, name: str = "main"):
        self.fn = fn
        self.depth = depth
        self.name = name
        self.lines: list[str] = []
        self._indent = INDENT * depth
        self._local_names: dict[int, str] = {}  # reg → nome do local
        self._build_local_map()

    def _build_local_map(self):
        """Mapeia registradores para nomes de locais via info de debug."""
        for (nm, start, end) in self.fn.locals:
            # registrador = índice na lista de locals até aquele ponto
            pass
        # Mapeamento simples: ordem de aparição
        seen = {}
        for i, (nm, start, end) in enumerate(self.fn.locals):
            if nm not in ("(for index)", "(for limit)", "(for step)", "(for generator)", "(for state)", "(for control)"):
                seen[i] = nm
        self._local_names = seen

    def _local_name(self, reg: int) -> str:
        """Tenta recuperar o nome original do local, senão usa r<N>."""
        # Busca por nome no mapa de locais
        for i, (nm, start, end) in enumerate(self.fn.locals):
            if i == reg:
                return nm
        return f"r{reg}"

    def _emit(self, line: str):
        self.lines.append(self._indent + line)

    def _emit_comment(self, text: str):
        self.lines.append(self._indent + f"-- {text}")

    def reconstruct(self) -> list[str]:
        fn = self.fn
        consts = fn.constants
        instrs = fn.instructions

        # Cabeçalho da função
        params = []
        for i in range(fn.num_params):
            nm = self._local_name(i)
            params.append(nm if nm != f"r{i}" else f"p{i}")
        if fn.is_vararg:
            params.append("...")

        if self.depth == 0:
            self._emit(f"-- Função principal | params={fn.num_params} upvals={fn.num_upvalues} stack={fn.max_stack}")
            if fn.source_name and fn.source_name != "?":
                src = fn.source_name.lstrip("@=")
                self._emit(f"-- Fonte original: {src}")
            self._emit("")
        else:
            param_str = ", ".join(params)
            self._emit(f"local function {self.name}({param_str})")

        # Reconstrução instrução por instrução
        i = 0
        pending_locals: dict[int, str] = {}
        declared: set[int] = set()

        # Pré-populando nomes de locais por reg
        local_reg_map: dict[int, str] = {}
        for idx, (nm, start_pc, end_pc) in enumerate(fn.locals):
            # Usa o reg = idx como aproximação
            if idx not in local_reg_map:
                local_reg_map[idx] = nm

        def reg_name(r: int) -> str:
            return local_reg_map.get(r, f"r{r}")

        while i < len(instrs):
            instr = instrs[i]
            op = instr.opcode
            A, B, C = instr.A, instr.B, instr.C
            Bx, sBx = instr.Bx, instr.sBx
            line_info = f"  -- linha {instr.line}" if instr.line > 0 else ""

            ra = reg_name(A)
            rb = reg_name(B)

            # Declaração de local se ainda não declarado
            def assign(target_reg: int, expr: str, comment: str = ""):
                nm = reg_name(target_reg)
                tail = f"  -- {comment}" if comment else ""
                if target_reg not in declared:
                    declared.add(target_reg)
                    self._emit(f"local {nm} = {expr}{line_info}{tail}")
                else:
                    self._emit(f"{nm} = {expr}{line_info}{tail}")

            # ── Despacho de opcodes ────────────────
            if op == 0:   # MOVE
                assign(A, reg_name(B))

            elif op == 1: # LOADK
                val = _fmt_const(consts[Bx], Bx) if Bx < len(consts) else f"K[{Bx}]"
                assign(A, val)

            elif op == 2: # LOADBOOL
                val = "true" if B else "false"
                assign(A, val)
                if C:
                    self._emit(f"-- (skip next)")

            elif op == 3: # LOADNIL
                nms = [reg_name(r) for r in range(A, B + 1)]
                for r in range(A, B + 1):
                    assign(r, "nil")

            elif op == 4: # GETUPVAL
                upnm = fn.upvalue_names[B] if B < len(fn.upvalue_names) else f"upval{B}"
                assign(A, upnm)

            elif op == 5: # GETGLOBAL
                gname = _fmt_const(consts[Bx], Bx) if Bx < len(consts) else f"G[{Bx}]"
                assign(A, gname.strip('"'))

            elif op == 6: # GETTABLE
                assign(A, f"{reg_name(B)}[{_rk(C, consts)}]")

            elif op == 7: # SETGLOBAL
                gname = (_fmt_const(consts[Bx], Bx) if Bx < len(consts) else f"G[{Bx}]").strip('"')
                self._emit(f"{gname} = {reg_name(A)}{line_info}")

            elif op == 8: # SETUPVAL
                upnm = fn.upvalue_names[B] if B < len(fn.upvalue_names) else f"upval{B}"
                self._emit(f"{upnm} = {reg_name(A)}{line_info}")

            elif op == 9: # SETTABLE
                self._emit(f"{reg_name(A)}[{_rk(B, consts)}] = {_rk(C, consts)}{line_info}")

            elif op == 10: # NEWTABLE
                assign(A, "{}")

            elif op == 11: # SELF
                assign(A + 1, reg_name(B))
                assign(A, f"{reg_name(B)}[{_rk(C, consts)}]")

            elif op in (12, 13, 14, 15, 16, 17): # aritmética
                ops_map = {12: "+", 13: "-", 14: "*", 15: "/", 16: "%", 17: "^"}
                assign(A, f"{_rk(B, consts)} {ops_map[op]} {_rk(C, consts)}")

            elif op == 18: # UNM
                assign(A, f"-{reg_name(B)}")

            elif op == 19: # NOT
                assign(A, f"not {reg_name(B)}")

            elif op == 20: # LEN
                assign(A, f"#{reg_name(B)}")

            elif op == 21: # CONCAT
                parts = [reg_name(r) for r in range(B, C + 1)]
                assign(A, " .. ".join(parts))

            elif op == 22: # JMP
                target = i + 1 + sBx
                self._emit(f"-- goto pc[{target}]{line_info}")

            elif op == 23: # EQ
                cmp = "==" if A == 0 else "~="
                self._emit(f"-- if {_rk(B, consts)} {cmp} {_rk(C, consts)} then skip{line_info}")

            elif op == 24: # LT
                cmp = "<" if A == 0 else ">="
                self._emit(f"-- if {_rk(B, consts)} {cmp} {_rk(C, consts)} then skip{line_info}")

            elif op == 25: # LE
                cmp = "<=" if A == 0 else ">"
                self._emit(f"-- if {_rk(B, consts)} {cmp} {_rk(C, consts)} then skip{line_info}")

            elif op in (26, 27): # TEST / TESTSET
                cond = "not " if C == 0 else ""
                self._emit(f"-- if {cond}{reg_name(A)} then skip{line_info}")

            elif op == 28: # CALL
                args = []
                if B == 0:
                    args = [reg_name(r) for r in range(A + 1, fn.max_stack)] + ["..."]
                else:
                    args = [reg_name(r) for r in range(A + 1, A + B)]

                if C == 0:
                    rets = f"r{A}..."
                    ret_str = f"local {rets} = "
                elif C == 1:
                    ret_str = ""
                else:
                    rets = [reg_name(A + r) for r in range(C - 1)]
                    for r_idx, ret_r in enumerate(range(A, A + C - 1)):
                        declared.add(ret_r)
                    ret_str = "local " + ", ".join(rets) + " = "

                call_str = f"{reg_name(A)}({', '.join(args)})"
                self._emit(f"{ret_str}{call_str}{line_info}")

            elif op == 29: # TAILCALL
                args = [reg_name(r) for r in range(A + 1, A + B)] if B > 0 else ["..."]
                self._emit(f"return {reg_name(A)}({', '.join(args)}){line_info}")

            elif op == 30: # RETURN
                if B == 0:
                    self._emit(f"return {reg_name(A)}, ...{line_info}")
                elif B == 1:
                    self._emit(f"return{line_info}")
                else:
                    rets = [reg_name(A + r) for r in range(B - 1)]
                    self._emit(f"return {', '.join(rets)}{line_info}")

            elif op == 31: # FORLOOP
                nm3 = reg_name(A + 3)
                self._emit(f"-- FORLOOP: {reg_name(A)} += {reg_name(A+2)}; {nm3} = {reg_name(A)}{line_info}")

            elif op == 32: # FORPREP
                self._emit(f"-- FORPREP: {reg_name(A)} -= {reg_name(A+2)}; jump{line_info}")

            elif op == 33: # TFORLOOP
                iters = [reg_name(A + 3 + r) for r in range(C)]
                self._emit(f"-- TFORLOOP: {', '.join(iters)} = {reg_name(A)}({reg_name(A+1)}, {reg_name(A+2)}){line_info}")

            elif op == 34: # SETLIST
                self._emit(f"-- SETLIST {reg_name(A)} B={B} C={C}{line_info}")

            elif op == 35: # CLOSE
                self._emit(f"-- CLOSE upvalues from {reg_name(A)}{line_info}")

            elif op == 36: # CLOSURE
                sub_fn = fn.functions[Bx] if Bx < len(fn.functions) else None
                sub_name = f"fn_{A}_{Bx}"
                if sub_fn:
                    sub_rec = FunctionReconstructor(sub_fn, self.depth + 1, sub_name)
                    sub_lines = sub_rec.reconstruct()
                    self.lines.extend(sub_lines)
                    self._emit("")
                assign(A, sub_name)

            elif op == 37: # VARARG
                if B == 0:
                    assign(A, "...")
                else:
                    for r in range(A, A + B - 1):
                        declared.add(r)
                    names = [reg_name(r) for r in range(A, A + B - 1)]
                    self._emit(f"local {', '.join(names)} = ...{line_info}")

            else:
                self._emit(f"-- OP_{op} A={A} B={B} C={C}{line_info}")

            i += 1

        if self.depth > 0:
            self._emit("end")
            self._emit("")

        return self.lines


def reconstruct_script(header: dict, main_fn: LuaFunction) -> str:
    """Reconstrói o script Lua completo a partir da função principal."""
    lines = []
    lines.append(f"-- Reconstruído por LuraphDeobfuscator")
    lines.append(f"-- Versão Lua: {header.get('version', '?')}")
    lines.append(f"-- Endianness: {'little' if header.get('little_endian') else 'big'}")
    lines.append("")

    rec = FunctionReconstructor(main_fn, depth=0, name="main")
    lines.extend(rec.reconstruct())

    return "\n".join(lines)
