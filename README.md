# LuraphDeobfuscator

Ferramenta de análise e desofuscação de scripts Lua protegidos pelo **Luraph Obfuscator** (v14.x).

> ⚠️ Use apenas em scripts de sua própria autoria ou com permissão explícita do detentor dos direitos.

---

## Como funciona

O Luraph empilha 4 camadas de proteção:

| Camada | O que faz | Como revertemos |
|---|---|---|
| 1. Codificação base85 | Payload codificado em string ASCII | `decoder.py` decodifica grupo a grupo |
| 2. Bytecode Lua | Código compilado em formato binário | `bytecode_parser.py` parseia o `.luac` |
| 3. Opcodes embaralhados | Instruções reordenadas na VM | `reconstructor.py` mapeia de volta |
| 4. Renomeação de símbolos | Variáveis viram `r0`, `r1`... | `cleaner.py` recupera nomes semânticos |

---

## Instalação

Requer **Python 3.10+** instalado.

```bash
# Clonar o repositório
git clone https://github.com/ExeDevelopment/LuraphDeobfuscator-Gemini-and-ChatGPT.git
cd luraph-deobfuscator

# Rodar direto com Python (sem instalar nada)
python main.py
```

---

## Uso

### Modo interativo (recomendado)
```bash
python main.py
```
O programa pede o caminho do arquivo `.lua` ofuscado. Pode arrastar o arquivo direto no terminal.

### Linha de comando direta
```bash
python main.py script_ofuscado.lua
python main.py script_ofuscado.lua -o resultado.lua
python main.py script_ofuscado.lua -v          # modo verbose
```

### Gerar o .exe (Windows)
```bash
python build.py
```
O `.exe` será gerado em `dist/LuraphDeobfuscator.exe`. Basta arrastar o `.lua` ofuscado para cima do `.exe` ou abrir e digitar o caminho.

---

## Estrutura do projeto

```
luraph-deobfuscator/
├── main.py              # CLI principal / interface interativa
├── decoder.py           # Extração e decodificação base85 do payload
├── bytecode_parser.py   # Parser de bytecode Lua 5.1
├── reconstructor.py     # Reconstrução de código Lua a partir do bytecode
├── cleaner.py           # Limpeza, renomeação de variáveis, remoção de junk
├── build.py             # Script para gerar o .exe com PyInstaller
└── README.md
```

---

## Limitações conhecidas

- **VM customizada**: o Luraph pode usar uma VM própria com opcodes completamente remapeados. Nesse caso o bytecode extraído é válido mas as instruções não correspondem diretamente ao padrão Lua 5.1. O parser tenta os mapeamentos mais comuns.
- **Lua 5.2+**: suporte parcial. O formato de header é diferente.
- **Sem descompilador completo**: a reconstrução gera código de nível de bytecode (registradores, gotos) — não é um decompilador de alto nível. Para reconstrução completa com `if/while/for`, combine com `unluac` ou `luadec` no bytecode extraído.
- **Strings criptografadas**: algumas versões do Luraph criptografam constantes strings adicionalmente. Nesse caso as strings aparecerão codificadas no output.

---

## Fluxo completo

```
arquivo.lua (ofuscado)
       │
       ▼
  decoder.py        → extrai payload base85 → decodifica → bytecode.luac
       │
       ▼
  bytecode_parser.py → parseia header, instruções, constantes, funções
       │
       ▼
  reconstructor.py  → converte instruções em código Lua linha por linha
       │
       ▼
  cleaner.py        → renomeia variáveis, remove junk, formata
       │
       ▼
  script_deobfuscated.lua
```

---

## Dependências

Nenhuma dependência externa para rodar. Só Python 3.10+ padrão.

Para gerar o `.exe`: `pip install pyinstaller` (feito automaticamente pelo `build.py`).
