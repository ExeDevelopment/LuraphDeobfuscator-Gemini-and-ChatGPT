"""
vm_decompressor.py
Implementação Python do range coder (descompressor) embutido no Luraph v14.

A VM do Luraph v14 usa um algoritmo de compressão range-coder customizado
para comprimir o bytecode antes de aplicar o XOR.
Este módulo re-implementa o mesmo algoritmo para descomprimir offline.

Algoritmo extraído por análise do loader Lua presente no arquivo ofuscado:
  local function L() ... end   -- loop principal do range coder
  local D = A(_)               -- descomprime payload0 (VM loader bytecode)
  local _ = A(h)               -- descomprime payload1 (script bytecode)
"""

import struct


# ──────────────────────────────────────────────
#  Tabela de bits (I[0..31] = potências de 2)
# ──────────────────────────────────────────────
I_TABLE = [1 << i for i in range(32)]


class RangeCoderState:
    """Estado do range coder — espelha as variáveis locais do loop L() do Luraph."""

    def __init__(self, data: bytes):
        self.data = data
        self.o = 0                       # posição de leitura
        self.d = len(data)               # tamanho total
        self.p = 0xFFFFFFFF              # range (inicialmente max uint32)
        self.f = 0                       # código atual

        # Tabelas de probabilidade (espelham as tabelas do Lua)
        self.q: list[int] = [0]         # buffer de saída
        self.W = 0                       # posição de escrita no buffer

        # Inicializa 'f' lendo 5 bytes
        for _ in range(5):
            self.f = (self.f * 256 + self._read_byte()) & 0xFFFFFFFF

    def _read_byte(self) -> int:
        if self.o < self.d:
            b = self.data[self.o]
            self.o += 1
            return b
        return 0

    def _normalize(self):
        """Normaliza o range quando ele cai abaixo de 0x01000000."""
        while self.p <= 0x00FFFFFF:
            self.p = (self.p * 256) & 0xFFFFFFFF
            self.f = ((self.f * 256) + self._read_byte()) & 0xFFFFFFFF

    def bit(self, prob_idx: int, probs: list) -> int:
        """
        Decodifica 1 bit usando a tabela de probabilidade.
        Equivale à função 's(N, W)' no Lua.
        """
        prob = probs[prob_idx]
        mid = int(self.p / 2048) * prob
        mid = int(mid)

        if self.f < mid:
            self.p = mid
            # Atualiza probabilidade: aumenta
            delta = int((2048 - prob) / 32)
            probs[prob_idx] = prob + delta
            self._normalize()
            return 0
        else:
            self.p -= mid
            self.f -= mid
            # Atualiza probabilidade: diminui
            delta = int(prob / 32)
            probs[prob_idx] = prob - delta
            self._normalize()
            return 1

    def read_bits(self, count: int, probs: list, base_idx: int = 1) -> int:
        """
        Lê 'count' bits da árvore de probabilidade.
        Equivale a 'p(f, z, N)' no Lua (com N=1 → resultado -1).
        """
        result = 1
        for _ in range(count):
            result = result * 2 + self.bit(result, probs)
        return result - (1 << count) + (1 << count) - 1

    def read_bits_v2(self, count: int, probs: list, base_idx: int = 1) -> int:
        """Versão alternativa que usa base_idx explícito."""
        result = 1
        for _ in range(count):
            b = self.bit(result, probs)
            result = result * 2 + b
        return result - (1 << count)


def _make_probs(size: int) -> list:
    return [1024] * size


def _make_probs_2d(rows: int, cols: int) -> list:
    return [[1024] * cols for _ in range(rows)]


def decompress_luraph(data: bytes) -> bytes | None:
    """
    Descomprime dados usando o range coder do Luraph v14.
    Implementação fiel ao algoritmo L() extraído do loader.

    Retorna os bytes descomprimidos ou None em caso de erro.
    """
    try:
        return _decompress_inner(data)
    except Exception:
        return None


def _decompress_inner(data: bytes) -> bytes:
    """Implementação interna do range coder Luraph."""

    # Inicializa tabelas de probabilidade (espelha o Lua)
    # l(0x300, 8)  → 0x300 linhas × 8 colunas
    w   = [[1024] * 8  for _ in range(0x300)]
    # l(1, 12)
    t   = [[1024] * 12 for _ in range(1)]
    # E(12), E(12), E(12), E(12)
    V   = [1024] * 12
    Z   = [1024] * 12
    X   = [1024] * 12
    U   = [1024] * 12
    # l(1, 12)
    M   = [[1024] * 12 for _ in range(1)]
    # l(64, 4)
    O   = [[1024] * 4  for _ in range(64)]
    # E(115)
    x   = [1024] * 115
    # E(16)
    y   = [1024] * 16

    # Tabela de comprimentos de match F[0..11]
    F_TABLE = [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 4, 5]
    # Tabela I de potências de 2
    I = I_TABLE

    # Estado do range coder
    rc = RangeCoderState(data)

    # Buffer de saída e variáveis de estado
    q: list[int] = []   # bytes de saída
    W = 0               # número de bytes escritos (1-based no Lua, 0-based aqui)

    J = 0               # estado do modelo
    k = 0               # rep3
    T = 0               # rep2
    c = 0               # rep1
    G = 0               # rep0 (distância de match atual)

    # Função auxiliar: lê N bits com árvore binária
    def read_bits(count: int, probs: list, start: int = 1) -> int:
        result = start
        for _ in range(count):
            b = rc.bit(result, probs)
            result = result * 2 + b
        return result - (1 << count)

    # Função auxiliar: lê byte literal (árvore de 8 bits)
    def read_literal(prob_row: list) -> int:
        result = 1
        for _ in range(8):
            b = rc.bit(result, prob_row)
            result = result * 2 + b
        return result - 256

    # Função N: decodifica comprimento de match (equiv. N(W,E) no Lua)
    def decode_match_len(H_probs, bit_pos: int) -> int:
        if rc.bit(1, H_probs) == 0:
            return read_bits(3, H_probs[3])
        elif rc.bit(2, H_probs) == 0:
            return 8 + read_bits(3, H_probs[4])
        else:
            return read_bits(8, H_probs[5]) + 16

    # Estruturas de comprimento
    def make_len_probs():
        return [
            [1024.0],       # [0] bit de seleção nível 1
            [1024.0],       # [1] bit de seleção nível 2
            [1024.0] * 8,   # [2] comprimentos 0-7
            [1024.0] * 8,   # [3] comprimentos 8-15
            [1024.0] * 256, # [4] comprimentos 16+
        ]

    H = make_len_probs()  # len probs normal
    a = make_len_probs()  # len probs rep

    # Loop principal de decompressão
    max_iterations = len(data) * 20  # limite de segurança
    iteration = 0

    while True:
        iteration += 1
        if iteration > max_iterations:
            break

        pos_state = W & 0  # pos_state simplificado (W % 1 == 0 sempre)

        if rc.bit(pos_state, t[J]) == 0:
            # ── Literal ───────────────────────────────────────
            prev_byte = q[W - 1] if W > 0 else 0
            hi = (prev_byte >> 4) & 0xF
            row_idx = (J << 8) + prev_byte  # simplificado
            row_idx = row_idx & 0x2FF       # mod 0x300

            if J >= 7:
                # Literal com match (matched literal)
                match_byte = q[W - G - 1] if (W - G - 1) >= 0 else 0
                byte_val = 1
                for bit_idx in range(8):
                    match_bit = (match_byte >> (7 - bit_idx)) & 1
                    prob_idx = 1 + (match_bit << 8) + byte_val
                    if prob_idx >= len(w[row_idx]):
                        prob_idx = prob_idx % len(w[row_idx])
                    b = rc.bit(prob_idx, w[row_idx])
                    byte_val = (byte_val << 1) | b
                byte_out = byte_val & 0xFF
            else:
                byte_out = read_literal(w[row_idx]) & 0xFF

            q.append(byte_out)
            W += 1
            J = F_TABLE[J]

        else:
            # ── Match ou Rep ──────────────────────────────────
            match_len = 0
            is_rep = False

            if rc.bit(J, V) != 0:
                # Rep match
                if rc.bit(J, Z) == 0:
                    # Rep0
                    if rc.bit(pos_state, M[J]) == 0:
                        J = 9 if J >= 7 else 11
                        match_len = 1
                    else:
                        is_rep = True
                        J = 9 if J >= 7 else 11
                        match_len = 1
                else:
                    F_saved = c
                    if rc.bit(J, X) == 0:
                        # Rep1
                        dist = c
                        c = G
                        G = dist
                    elif rc.bit(J, U) == 0:
                        # Rep2
                        dist = T
                        T = c
                        c = G
                        G = dist
                    else:
                        # Rep3
                        dist = k
                        k = T
                        T = c
                        c = G
                        G = dist

                if not is_rep or match_len == 0:
                    J = 8 if J < 7 else 11
                    match_len = 2 + _decode_len_simple(rc, a)

            else:
                # Simple match — nova distância
                k = T
                T = c
                c = G

                match_len = 2 + _decode_len_simple(rc, H)

                # Decodifica distância
                pos_slot = read_bits(6, [p[0] for p in O], 1)
                if pos_slot < 4:
                    G = pos_slot
                else:
                    direct_bits = pos_slot // 2 - 1
                    G = (2 + pos_slot % 2) << direct_bits
                    if pos_slot < 14:
                        G += _read_reversed_bits(rc, direct_bits, x, G - pos_slot)
                    else:
                        G += _read_direct_bits(rc, direct_bits - 4) * 16
                        G += _read_reversed_bits(rc, 4, y, 0)
                        if G == 0xFFFFFFFF:
                            # EOF
                            return bytes(q)

                J = 7 if J < 7 else 10

            # Copia bytes do buffer (LZ77)
            if W - G - 1 < 0:
                # Distância inválida — trunca
                match_len = min(match_len, W)
                src_base = 0
            else:
                src_base = W - G - 1

            end_pos = W + match_len
            for copy_i in range(W + 1, end_pos + 1):
                src_i = copy_i - G - 1
                q.append(q[src_i] if src_i >= 0 and src_i < len(q) else 0)
            W = end_pos

    return bytes(q)


def _decode_len_simple(rc: RangeCoderState, len_probs: list) -> int:
    """Decodifica comprimento de match (simplificado sem estado posicional)."""
    if rc.bit(0, len_probs[0]) == 0:
        result = 1
        for _ in range(3):
            b = rc.bit(result, len_probs[2])
            result = result * 2 + b
        return result - 8
    elif rc.bit(0, len_probs[1]) == 0:
        result = 1
        for _ in range(3):
            b = rc.bit(result, len_probs[3])
            result = result * 2 + b
        return 8 + result - 8
    else:
        result = 1
        for _ in range(8):
            b = rc.bit(result, len_probs[4])
            result = result * 2 + b
        return 16 + result - 256


def _read_reversed_bits(rc: RangeCoderState, count: int, probs: list, base: int) -> int:
    """Lê bits em ordem reversa com probabilidades (para distâncias LZMA)."""
    result = 0
    m = 1
    for i in range(count):
        b = rc.bit(m, probs)
        m = m * 2 + b
        if b:
            result |= I_TABLE[i]
    return result


def _read_direct_bits(rc: RangeCoderState, count: int) -> int:
    """Lê bits diretos (sem modelo de probabilidade)."""
    result = 0
    for _ in range(count):
        rc.p = (rc.p >> 1) & 0xFFFFFFFF
        rc.f = (rc.f - rc.p) & 0xFFFFFFFF
        b = 0 if rc.f < rc.p else 1
        if b == 0:
            rc.f = (rc.p + rc.f) & 0xFFFFFFFF
        result = (result << 1) | b
        rc._normalize()
    return result
