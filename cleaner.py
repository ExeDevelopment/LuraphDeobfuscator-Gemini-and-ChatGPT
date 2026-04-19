"""
cleaner.py
Pós-processamento do código Lua reconstruído:
- Detecta e renomeia variáveis ofuscadas (r0, r1...)
- Remove comentários de junk code
- Formata indentação
- Heurísticas para recuperar nomes semânticos de globais conhecidas
"""

import re


# ──────────────────────────────────────────────
#  Mapa de globais Lua conhecidas → nomes legíveis
# ──────────────────────────────────────────────
KNOWN_GLOBALS = {
    # Standard lib
    "print", "tostring", "tonumber", "type", "pairs", "ipairs",
    "next", "select", "unpack", "rawget", "rawset", "rawequal",
    "setmetatable", "getmetatable", "require", "load", "loadstring",
    "loadfile", "dofile", "error", "assert", "pcall", "xpcall",
    "collectgarbage", "gcinfo", "newproxy",
    # String
    "string", "string.format", "string.len", "string.sub",
    "string.byte", "string.char", "string.rep", "string.reverse",
    "string.upper", "string.lower", "string.find", "string.match",
    "string.gmatch", "string.gsub", "string.dump",
    # Table
    "table", "table.insert", "table.remove", "table.sort",
    "table.concat", "table.getn", "table.maxn", "table.move",
    # Math
    "math", "math.abs", "math.ceil", "math.floor", "math.sqrt",
    "math.sin", "math.cos", "math.tan", "math.max", "math.min",
    "math.random", "math.randomseed", "math.huge", "math.pi",
    # IO
    "io", "io.read", "io.write", "io.open", "io.close",
    "io.lines", "io.flush",
    # OS
    "os", "os.time", "os.clock", "os.date", "os.exit",
    # Coroutine
    "coroutine", "coroutine.create", "coroutine.resume",
    "coroutine.yield", "coroutine.wrap", "coroutine.status",
    # Misc
    "_G", "_VERSION", "arg",
}

# Luraph frequentemente aliasa estas funções no loader
LURAPH_ALIASES = {
    "pcall":        ["R"],
    "setmetatable": ["D"],
    "string.gsub":  ["_"],
    "string.sub":   ["h"],
    "string.char":  ["S"],
    "string.pack":  ["u"],
    "loadstring":   ["g"],
    "unpack":       ["Q"],
    "string.byte":  ["C"],
    "tostring":     ["i"],
}


def _build_alias_reverse() -> dict[str, str]:
    rev = {}
    for real, aliases in LURAPH_ALIASES.items():
        for a in aliases:
            rev[a] = real
    return rev


ALIAS_REVERSE = _build_alias_reverse()


# ──────────────────────────────────────────────
#  Renomeação de registradores
# ──────────────────────────────────────────────

def rename_registers(code: str) -> str:
    """
    Substitui r0, r1... por nomes mais legíveis quando possível.
    Estratégia: detectar padrões como 'local r5 = print' e usar 'print' como nome.
    """
    lines = code.split("\n")
    reg_map: dict[str, str] = {}

    # Primeira passagem: coleta mapeamentos
    for line in lines:
        # local rN = <nome_global>
        m = re.match(r"^\s*local (r\d+) = ([a-zA-Z_][a-zA-Z0-9_.]*)\s*$", line)
        if m:
            reg = m.group(1)
            val = m.group(2)
            if val in KNOWN_GLOBALS or "." in val:
                # Usa o último segmento como nome
                short = val.split(".")[-1]
                if short not in reg_map.values():
                    reg_map[reg] = short

        # local rN = "string" → usa 'str_N'
        m2 = re.match(r'^\s*local (r\d+) = "([^"]{1,20})"\s*$', line)
        if m2:
            reg = m2.group(1)
            val = m2.group(2)
            # Só renomeia se for string curta e identificável
            if val.isalpha() and len(val) <= 12:
                candidate = f"s_{val[:8]}"
                if candidate not in reg_map.values():
                    reg_map[reg] = candidate

    if not reg_map:
        return code

    # Segunda passagem: substitui nos comentários e código
    result = []
    for line in lines:
        for old, new in sorted(reg_map.items(), key=lambda x: -len(x[0])):
            # Substitui apenas como palavra inteira
            line = re.sub(r'\b' + re.escape(old) + r'\b', new, line)
        result.append(line)

    return "\n".join(result)


# ──────────────────────────────────────────────
#  Remoção de junk / ruído
# ──────────────────────────────────────────────

JUNK_PATTERNS = [
    # Gotos para PC vizinho imediato (NOPs)
    r"^\s*-- goto pc\[\d+\]\s*$",
    # Linhas só com comentário de skip trivial
    r"^\s*-- \(skip next\)\s*$",
    # FORLOOP/FORPREP raw (mantém o comentário mas marca)
    # Linhas de close sem uso
    r"^\s*-- CLOSE upvalues.*$",
]

_JUNK_RE = [re.compile(p) for p in JUNK_PATTERNS]


def remove_junk(code: str) -> str:
    """Remove linhas de junk code / instruções sem efeito."""
    lines = code.split("\n")
    cleaned = []
    for line in lines:
        is_junk = any(p.match(line) for p in _JUNK_RE)
        if not is_junk:
            cleaned.append(line)
    return "\n".join(cleaned)


# ──────────────────────────────────────────────
#  Limpeza de linhas em branco excessivas
# ──────────────────────────────────────────────

def normalize_blank_lines(code: str) -> str:
    """Remove mais de 2 linhas em branco consecutivas."""
    return re.sub(r"\n{3,}", "\n\n", code)


# ──────────────────────────────────────────────
#  Detecção de padrões de constantes no loader
# ──────────────────────────────────────────────

def annotate_known_patterns(code: str) -> str:
    """
    Adiciona anotações quando detecta padrões típicos do Luraph:
    - Verificação de versão Lua
    - Decodificador base85
    - pcall de segurança
    """
    notes = []

    if "0x1B" in code and "0x4C" in code:
        notes.append("-- [NOTA] Detectado: verificação de assinatura Lua (\\x1BLua)")
    if "52200625" in code or "614125" in code:
        notes.append("-- [NOTA] Detectado: decodificador base85 do Luraph")
    if "string.pack" in code and "<I4" in code:
        notes.append("-- [NOTA] Detectado: empacotamento little-endian uint32")

    if notes:
        header = "\n".join(notes) + "\n\n"
        return header + code

    return code


# ──────────────────────────────────────────────
#  Pipeline completo
# ──────────────────────────────────────────────

def clean(code: str) -> str:
    """Aplica todas as transformações de limpeza em sequência."""
    code = rename_registers(code)
    code = remove_junk(code)
    code = normalize_blank_lines(code)
    return code
