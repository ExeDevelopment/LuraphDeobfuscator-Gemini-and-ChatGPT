"""
build.py
Compila o projeto em um único .exe usando PyInstaller.
Execute: python build.py
"""

import subprocess
import sys
import os


def main():
    print("Instalando PyInstaller...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyinstaller", "--quiet"])

    print("Compilando .exe...")

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",                        # tudo em 1 .exe
        "--console",                        # janela de prompt de comando
        "--name", "LuraphDeobfuscator",
        "--add-data", f"decoder.py{os.pathsep}.",
        "--add-data", f"bytecode_parser.py{os.pathsep}.",
        "--add-data", f"reconstructor.py{os.pathsep}.",
        "--add-data", f"cleaner.py{os.pathsep}.",
        "main.py",
    ]

    subprocess.check_call(cmd)

    exe_path = os.path.join("dist", "LuraphDeobfuscator.exe")
    if os.path.isfile(exe_path):
        size = os.path.getsize(exe_path) // 1024
        print(f"\n.exe gerado com sucesso: {exe_path} ({size} KB)")
    else:
        print("\nAVISO: .exe não encontrado em dist/. Verifique os logs acima.")


if __name__ == "__main__":
    main()
