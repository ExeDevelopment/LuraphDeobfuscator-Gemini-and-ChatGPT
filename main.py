"""
main.py
LuraphDeobfuscator — Interface de linha de comando.
Uso:
    python main.py                  -> modo interativo (drag & drop ou digitar caminho)
    python main.py arquivo.lua      -> processa direto
    python main.py arquivo.lua -o saida.lua
    python main.py arquivo.lua -v   -> verbose
"""

import sys
import os
import argparse
import traceback

from decoder import full_decode, DecoderResult, is_luraph, load_file
from bytecode_parser import BytecodeParser
from reconstructor import reconstruct_script
from cleaner import clean


# ──────────────────────────────────────────────
#  Cores ANSI
# ──────────────────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    DIM    = "\033[2m"


def _supports_color():
    if os.name == "nt":
        os.system("")  # ativa ANSI no Windows 10+
        return True
    return sys.stdout.isatty()


USE_COLOR = _supports_color()


def c(color, text):
    return (color + text + C.RESET) if USE_COLOR else text


# ──────────────────────────────────────────────
#  Banner
# ──────────────────────────────────────────────
BANNER = r"""
  _                           _       ___       _           _
 | |   _   _ _ __ __ _ _ __ | |__   /   \  ___| |__  _   _| |_ ___ _ __
 | |  | | | | '__/ _` | '_ \| '_ \ / /\ / / _ \ '_ \| | | | __/ _ \ '__|
 | |__| |_| | | | (_| | |_) | | | / /_// |  __/ |_) | |_| | ||  __/ |
 |_____\__,_|_|  \__,_| .__/|_| |_/___,'   \___|_.__/ \__,_|\__\___|_|
                       |_|
"""


def print_banner():
    print(c(C.CYAN, BANNER))
    print(c(C.DIM, "  Ferramenta de analise e desobfuscacao de scripts Luraph"))
    print(c(C.DIM, "  Baseada na analise real do formato Luraph v14.x\n"))


# ──────────────────────────────────────────────
#  Helpers de output
# ──────────────────────────────────────────────

def step(n, total, msg):
    print(c(C.CYAN, f"[{n}/{total}] ") + msg)

def ok(msg):
    print(c(C.GREEN, "  OK — ") + msg)

def warn(msg):
    print(c(C.YELLOW, "  AVISO: ") + msg)

def err(msg):
    print(c(C.RED, "  ERRO: ") + msg)

def info(msg):
    print(c(C.DIM, "  " + msg))

def sep():
    print(c(C.DIM, "  " + "─" * 48))


# ──────────────────────────────────────────────
#  Salvar arquivo
# ──────────────────────────────────────────────

def save(path, content, mode="w", encoding="utf-8"):
    if mode == "wb":
        with open(path, "wb") as f:
            f.write(content)
    else:
        with open(path, "w", encoding=encoding) as f:
            f.write(content)
    kb = os.path.getsize(path) // 1024 or 1
    info(f"Salvo: {path}  ({kb} KB)")


# ──────────────────────────────────────────────
#  Pipeline de desofuscacao
# ──────────────────────────────────────────────

def deobfuscate(input_path, output_path=None, verbose=False):
    """
    Pipeline completo. Retorna True em sucesso total,
    False em falha, ou 'partial' em sucesso parcial.
    """
    TOTAL_STEPS = 5
    base = os.path.splitext(output_path if output_path else os.path.join(os.getcwd(), os.path.basename(input_path)))[0]
    if output_path is None:
        output_path = base + "_deobfuscated.lua"

    print()

    # ── Passo 1: Leitura e validação ──────────
    step(1, TOTAL_STEPS, f"Lendo arquivo: {os.path.basename(input_path)}")
    if not os.path.isfile(input_path):
        err(f"Arquivo nao encontrado: {input_path}")
        return False
    try:
        source = load_file(input_path)
    except Exception as e:
        err(f"Falha ao ler: {e}")
        return False

    size_kb = os.path.getsize(input_path) // 1024
    ok(f"{size_kb} KB lidos")

    if not is_luraph(source):
        warn("Header do Luraph nao encontrado — tentando mesmo assim.")
    else:
        info(f"Luraph detectado — versao no header confirmada.")

    # ── Passo 2: Decodificacao base85 ─────────
    step(2, TOTAL_STEPS, "Decodificando payloads base85...")
    result = full_decode(input_path)

    if not result.payloads_decoded:
        err("Nenhum payload encontrado. Arquivo pode estar corrompido.")
        return False

    for i, dec in enumerate(result.payloads_decoded):
        label = ["VM loader", "Script real"][i] if i < 2 else f"Payload {i}"
        ok(f"Payload {i} ({label}): {len(dec):,} bytes decodificados")

    for w in result.warnings:
        warn(w)

    if verbose:
        for i, dec in enumerate(result.payloads_decoded):
            info(f"  Payload {i} — primeiros bytes: {dec[:16].hex()}")

    # Salvar binarios brutos sempre
    for i, dec in enumerate(result.payloads_decoded):
        raw_path = f"{base}_payload{i}.bin"
        save(raw_path, dec, mode="wb")

    # ── Passo 3: Tentativa de parse do bytecode ──
    step(3, TOTAL_STEPS, "Tentando parsear bytecode Lua...")
    parsed = False
    header = None
    main_fn = None

    if result.is_standard_lua and result.script_bytecode:
        bytecode = result.script_bytecode
        if result.xor_key:
            info(f"XOR key usada: {result.xor_key.hex()}")
        try:
            parser = BytecodeParser(bytecode)
            header, main_fn = parser.parse()
            ok(f"Lua {header['version']} | "
               f"{len(main_fn.instructions)} instrucoes | "
               f"{len(main_fn.constants)} constantes | "
               f"{len(main_fn.functions)} sub-funcoes")
            parsed = True
        except Exception as e:
            warn(f"Parser falhou: {e}")
            if verbose:
                traceback.print_exc()
    else:
        warn("Bytecode criptografado com chave runtime — parse direto nao e possivel.")
        info("O Luraph v14 usa VM customizada com criptografia derivada do ambiente.")
        info("Os binarios brutos foram salvos para analise com ferramentas externas.")

    # ── Passo 4: Reconstrucao ou analise parcial ──
    step(4, TOTAL_STEPS, "Reconstruindo/analisando conteudo...")
    output_lines = []
    output_lines.append("-- ============================================================")
    output_lines.append("-- Gerado por LuraphDeobfuscator")
    output_lines.append(f"-- Arquivo original: {os.path.basename(input_path)}")
    output_lines.append(f"-- Versao Luraph detectada: {result.version}")
    output_lines.append(f"-- Payloads extraidos: {len(result.payloads_decoded)}")
    output_lines.append("-- ============================================================")
    output_lines.append("")

    if parsed and header and main_fn:
        # Reconstrucao completa
        try:
            reconstructed = reconstruct_script(header, main_fn)
            cleaned = clean(reconstructed)
            output_lines.append(cleaned)
            ok(f"{len(cleaned.splitlines())} linhas reconstruidas")
        except Exception as e:
            warn(f"Reconstrucao falhou: {e}")
            if verbose:
                traceback.print_exc()
            parsed = False

    if not parsed:
        # Analise parcial: strings + estrutura do loader
        output_lines.append("-- ============================================================")
        output_lines.append("-- MODO PARCIAL: bytecode criptografado, exibindo analise")
        output_lines.append("-- ============================================================")
        output_lines.append("")

        # Strings legíveis extraídas
        if result.strings:
            output_lines.append(f"-- {len(result.strings)} strings legíveis encontradas nos payloads:")
            output_lines.append("")
            for i, s in enumerate(result.strings[:200]):  # máx 200
                escaped = s.replace("\\", "\\\\").replace('"', '\\"')
                output_lines.append(f'-- [{i+1:03d}] "{escaped}"')
            if len(result.strings) > 200:
                output_lines.append(f"-- ... e mais {len(result.strings)-200} strings")
            ok(f"{min(len(result.strings), 200)} strings legíveis extraídas")
        else:
            output_lines.append("-- Nenhuma string legível encontrada.")

        output_lines.append("")
        output_lines.append("-- ============================================================")
        output_lines.append("-- PROXIMOS PASSOS PARA DESOBFUSCAR COMPLETAMENTE:")
        output_lines.append("-- 1. Use os arquivos _payload0.bin e _payload1.bin gerados")
        output_lines.append("-- 2. Tente: java -jar unluac.jar _payload1.bin > saida.lua")
        output_lines.append("-- 3. Ou tente: luadec _payload1.bin > saida.lua")
        output_lines.append("-- 4. O payload0.bin e a VM/loader — analise-o para encontrar")
        output_lines.append("--    a logica de descriptografia e a chave runtime.")
        output_lines.append("-- ============================================================")

    # ── Passo 5: Salvar resultado ──────────────
    step(5, TOTAL_STEPS, "Salvando resultado...")
    final_content = "\n".join(output_lines)
    try:
        save(output_path, final_content)
    except Exception as e:
        err(f"Falha ao salvar: {e}")
        return False

    # Resumo final
    print()
    sep()
    if parsed:
        print(c(C.GREEN + C.BOLD, "  DESOBFUSCACAO COMPLETA"))
    else:
        print(c(C.YELLOW + C.BOLD, "  ANALISE PARCIAL CONCLUIDA"))
    info(f"Entrada  : {input_path}")
    info(f"Saida    : {output_path}")
    for i, dec in enumerate(result.payloads_decoded):
        info(f"Binario {i} : {base}_payload{i}.bin  ({len(dec):,} bytes)")
    sep()
    print()

    return True if parsed else "partial"


# ──────────────────────────────────────────────
#  Modo interativo
# ──────────────────────────────────────────────

def interactive_mode():
    print_banner()
    print(c(C.WHITE, "  Modo interativo"))
    print(c(C.DIM,   "  Cole ou arraste o arquivo .lua ofuscado para o terminal\n"))
    print(c(C.DIM,   "  Digite 'sair' para encerrar\n"))

    while True:
        try:
            raw = input(c(C.CYAN, "  Arquivo .lua > ")).strip().strip('"').strip("'")
        except (KeyboardInterrupt, EOFError):
            print(c(C.DIM, "\n\n  Saindo..."))
            break

        if not raw:
            continue
        if raw.lower() in ("sair", "exit", "quit", "q"):
            print(c(C.DIM, "\n  Saindo..."))
            break
        if not os.path.isfile(raw):
            err(f"Arquivo nao encontrado: {raw}")
            print()
            continue

        # Output customizado?
        try:
            out_raw = input(c(C.DIM, "  Saida (Enter = padrao): ")).strip().strip('"').strip("'")
        except (KeyboardInterrupt, EOFError):
            break
        out_path = out_raw if out_raw else None

        # Verbose?
        try:
            v_ans = input(c(C.DIM, "  Verbose? [s/N]: ")).strip().lower()
        except (KeyboardInterrupt, EOFError):
            break
        verbose = v_ans in ("s", "sim", "y", "yes")

        deobfuscate(raw, out_path, verbose)

        try:
            again = input(c(C.DIM, "  Processar outro? [Enter = sim / q = sair]: ")).strip().lower()
        except (KeyboardInterrupt, EOFError):
            break
        if again in ("q", "sair", "exit"):
            print(c(C.DIM, "\n  Saindo..."))
            break
        print()


# ──────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="LuraphDeobfuscator",
        description="Desobfusca / analisa scripts Lua protegidos pelo Luraph.",
    )
    parser.add_argument("input",  nargs="?", help="Arquivo .lua ofuscado")
    parser.add_argument("-o", "--output",  help="Arquivo de saida (padrao: <nome>_deobfuscated.lua)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verbose")

    args = parser.parse_args()

    if args.input:
        print_banner()
        if not os.path.isfile(args.input):
            err(f"Arquivo nao encontrado: {args.input}")
            sys.exit(1)
        result = deobfuscate(args.input, args.output, args.verbose)
        sys.exit(0 if result else 1)
    else:
        interactive_mode()


if __name__ == "__main__":
    main()
