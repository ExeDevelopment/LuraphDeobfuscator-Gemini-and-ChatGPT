"""
decoder.py
Extrai e decodifica os payloads base85 embutidos em scripts Luraph.
Baseado na análise do formato Luraph v14.x.

Estrutura real do Luraph v14:
  local _,h = B([=[ PAYLOAD_VM ]=]), B([==[ PAYLOAD_SCRIPT ]==])

  - PAYLOAD_VM     : bytecode do loader/VM customizada do Luraph (~24 KB)
  - PAYLOAD_SCRIPT : bytecode do script real (~centenas de KB)

  Ambos são codificados em base85 customizado e passam por criptografia
  adicional (XOR ou similar) derivada do ambiente de execução.
  Por isso os bytes decodificados NÃO começam com \\x1bLua diretamente.

O que esta ferramenta consegue fazer:
  1. Extrair e decodificar os dois payloads base85  (determinístico)
  2. Salvar os binários brutos para análise externa
  3. Tentar parsear se houver assinatura Lua padrão (sem criptografia extra)
  4. Extrair constantes strings legíveis que sobrevivem à criptografia
  5. Reconstruir estrutura parcial do script

Limitação: a chave de criptografia da VM é derivada em runtime — sem
executar o loader, não é possível descriptografar o PAYLOAD_SCRIPT
automaticamente de forma determinística.
"""

import re
import struct
import os


# ──────────────────────────────────────────────
#  Constantes
# ──────────────────────────────────────────────
LUA_SIGNATURE   = b"\x1bLua"
LUAJIT_SIG      = b"\x1bLJ"
LURAPH_COMMENT  = "-- This file was protected using Luraph"


# ──────────────────────────────────────────────
#  Base85 Luraph
# ──────────────────────────────────────────────

def decode_base85(payload: str) -> bytes:
    """
    Decodifica payload base85 customizado do Luraph.
    - Expande 'z' → '!!!!!' (run-length de zeros)
    - Grupos de 5 chars → 4 bytes uint32 little-endian
    - Fórmula: d = sum(char[i]-33) * 85^(4-i)
    """
    payload = payload.replace("z", "!!!!!")
    result = bytearray()
    i = 0
    while i + 5 <= len(payload):
        chunk = payload[i:i+5]
        n = 0
        valid = True
        for ch in chunk:
            v = ord(ch) - 33
            if v < 0 or v > 84:
                valid = False
                break
            n = n * 85 + v
        if valid:
            try:
                result += struct.pack("<I", n & 0xFFFFFFFF)
            except struct.error:
                result += b"\x00\x00\x00\x00"
        i += 5
    return bytes(result)


# ──────────────────────────────────────────────
#  Extração de payloads
# ──────────────────────────────────────────────

def extract_all_payloads(source: str) -> list[str]:
    """
    Extrai todos os payloads B([=*[ ... ]=*]) do arquivo.
    O Luraph v14 tem exatamente 2: VM loader e script real.
    """
    pattern = r'B\(\[([=]*)\[([\s\S]*?)\]\1\]\)'
    matches = re.findall(pattern, source)
    return [m[1] for m in matches]


def extract_payload(source: str) -> str | None:
    """Compatibilidade: retorna o primeiro payload encontrado."""
    payloads = extract_all_payloads(source)
    return payloads[0] if payloads else None


# ──────────────────────────────────────────────
#  Extração de strings do binário bruto
# ──────────────────────────────────────────────

def extract_readable_strings(data: bytes, min_len: int = 4) -> list[str]:
    """
    Extrai strings ASCII legíveis do binário bruto.
    Útil mesmo quando o bytecode está criptografado.
    """
    results = []
    current = []
    for b in data:
        if 0x20 <= b <= 0x7E:  # ASCII imprimível
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                s = "".join(current)
                # Filtra strings que parecem ser código/texto real
                if any(c.isalpha() for c in s):
                    results.append(s)
            current = []
    if len(current) >= min_len:
        results.append("".join(current))
    return results


def filter_lua_strings(strings: list[str]) -> list[str]:
    """
    Filtra strings que parecem ser identificadores Lua, nomes de funções
    ou literais de código.
    """
    lua_keywords = {
        "local", "function", "return", "if", "then", "else", "elseif",
        "end", "for", "while", "do", "repeat", "until", "and", "or",
        "not", "nil", "true", "false", "in", "break",
    }
    lua_globals = {
        "print", "tostring", "tonumber", "type", "pairs", "ipairs",
        "pcall", "xpcall", "error", "assert", "require", "loadstring",
        "setmetatable", "getmetatable", "rawget", "rawset", "select",
        "unpack", "string", "table", "math", "io", "os", "coroutine",
    }
    relevant = []
    for s in strings:
        words = re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', s)
        if any(w in lua_keywords or w in lua_globals for w in words):
            relevant.append(s)
        elif len(s) >= 8 and s.count('.') >= 1:  # caminhos de arquivo
            relevant.append(s)
        elif len(s) >= 6 and s[0].isupper():     # identificadores capitalizados
            relevant.append(s)
    return list(dict.fromkeys(relevant))  # deduplica mantendo ordem


# ──────────────────────────────────────────────
#  Tentativa de descriptografia simples (XOR)
# ──────────────────────────────────────────────

def try_xor_decrypt(data: bytes) -> tuple[bytes | None, int]:
    """
    Tenta encontrar chave XOR de 1 byte que transforme data[:4] em \\x1bLua.
    Retorna (dados_descriptografados, chave) ou (None, 0).
    """
    target = LUA_SIGNATURE
    if len(data) < 4:
        return None, 0

    # Tenta XOR byte único
    for key in range(256):
        if (data[0] ^ key) == target[0]:
            candidate = bytes(b ^ key for b in data)
            if candidate[:4] == target:
                return candidate, key
    return None, 0


def try_xor_decrypt_multibyte(data: bytes, key_len: int = 4) -> tuple[bytes | None, bytes]:
    """
    Tenta chave XOR de múltiplos bytes derivada dos primeiros bytes
    supondo que o plaintext começa com \\x1bLua.
    """
    if len(data) < key_len:
        return None, b""

    # Deriva chave dos primeiros bytes
    key = bytes(data[i] ^ LUA_SIGNATURE[i % len(LUA_SIGNATURE)] for i in range(key_len))

    # Aplica XOR cíclico
    decrypted = bytes(data[i] ^ key[i % key_len] for i in range(len(data)))

    if decrypted[:4] == LUA_SIGNATURE:
        return decrypted, key
    return None, b""


# ──────────────────────────────────────────────
#  Utilitários
# ──────────────────────────────────────────────

def is_luraph(source: str) -> bool:
    return LURAPH_COMMENT in source


def detect_version(source: str) -> str:
    m = re.search(r'Luraph Obfuscator v([\d.]+)', source)
    return m.group(1) if m else "desconhecida"


def load_file(path: str) -> str:
    for enc in ("utf-8", "latin-1", "cp1252"):
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read()
        except UnicodeDecodeError:
            continue
    raise ValueError(f"Não foi possível ler: {path}")


# ──────────────────────────────────────────────
#  Pipeline principal
# ──────────────────────────────────────────────

class DecoderResult:
    """Resultado completo da extração."""
    def __init__(self):
        self.version: str = "?"
        self.payloads_raw: list[str] = []          # payloads base85 originais
        self.payloads_decoded: list[bytes] = []    # binários decodificados
        self.vm_bytecode: bytes | None = None      # payload 0 (VM loader)
        self.script_bytecode: bytes | None = None  # payload 1 (script real)
        self.is_standard_lua: bool = False         # tem assinatura \x1bLua?
        self.xor_key: bytes = b""                  # chave XOR se encontrada
        self.strings: list[str] = []               # strings legíveis extraídas
        self.status: str = ""
        self.warnings: list[str] = []


def full_decode(path: str) -> DecoderResult:
    """
    Pipeline completo de extração e análise.
    Sempre retorna um DecoderResult com tudo que foi possível extrair.
    """
    r = DecoderResult()

    source = load_file(path)
    r.version = detect_version(source)

    if not is_luraph(source):
        r.warnings.append("Arquivo não tem header do Luraph — tentando mesmo assim.")

    # 1. Extrair payloads base85
    r.payloads_raw = extract_all_payloads(source)
    if not r.payloads_raw:
        r.status = "ERRO: nenhum payload B([=[ encontrado."
        return r

    # 2. Decodificar cada payload
    for i, p in enumerate(r.payloads_raw):
        decoded = decode_base85(p)
        r.payloads_decoded.append(decoded)

    # 3. Atribuir VM e script
    r.vm_bytecode     = r.payloads_decoded[0] if len(r.payloads_decoded) > 0 else None
    r.script_bytecode = r.payloads_decoded[1] if len(r.payloads_decoded) > 1 else r.vm_bytecode

    # 4. Verificar assinatura Lua no script
    target = r.script_bytecode or r.vm_bytecode or b""
    if target[:4] == LUA_SIGNATURE:
        r.is_standard_lua = True
        r.status = "OK — bytecode Lua padrão detectado"
    elif target[:3] == LUAJIT_SIG:
        r.is_standard_lua = True
        r.warnings.append("Formato LuaJIT detectado.")
        r.status = "OK — LuaJIT"
    else:
        # Tentar descriptografar
        dec1, key1 = try_xor_decrypt(target)
        if dec1:
            r.script_bytecode = dec1
            r.xor_key = bytes([key1])
            r.is_standard_lua = True
            r.status = f"OK — descriptografado com XOR key=0x{key1:02x}"
        else:
            dec2, key2 = try_xor_decrypt_multibyte(target)
            if dec2:
                r.script_bytecode = dec2
                r.xor_key = key2
                r.is_standard_lua = True
                r.status = f"OK — descriptografado com XOR key={key2.hex()}"
            else:
                r.warnings.append(
                    "Bytecode criptografado com chave derivada em runtime. "
                    "Descriptografia automática não é possível sem executar o loader."
                )
                r.status = "PARCIAL — payload extraído mas criptografado"

    # 5. Extrair strings legíveis de TODOS os payloads
    all_strings = []
    for decoded in r.payloads_decoded:
        all_strings.extend(extract_readable_strings(decoded))
    r.strings = filter_lua_strings(all_strings)

    return r


def extract_bytecode(path: str) -> tuple[bytes | None, str]:
    """Compatibilidade com versão anterior."""
    result = full_decode(path)
    if result.is_standard_lua:
        return result.script_bytecode, result.status
    if result.script_bytecode:
        return result.script_bytecode, result.status
    return None, result.status
