#!/usr/bin/env python3
"""Hall of Mirrors (hiCTF 2026). Usage: python3 solve.py hall-of-mirrors.wav"""
import mmap
import re
import struct
import sys
import zlib

from ecdsa.curves import SECP256k1
from fpylll import CVP, LLL, IntegerMatrix

MASK = (1 << 64) - 1
GOLDEN = 0x9E3779B97F4A7C15
FNV = 0x100000001B3
SEED = 0x9C4F1E7A3B50D682  # Read from the spectrogram.


def rol(x, n):
    n &= 63
    return ((x << n) | (x >> (64 - n))) & MASK if n else x


def splitmix(s):
    s = (s + GOLDEN) & MASK
    x = s
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & MASK
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & MASK
    return s, (x ^ (x >> 31)) & MASK


def extract(wav):
    with open(wav, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        if mm[:4] != b'RIFF' or mm[8:12] != b'WAVE':
            raise ValueError('Expected a RIFF/WAVE file')
        off = 12
        while off + 8 <= len(mm):
            kind, size = struct.unpack_from('<4sI', mm, off)
            if kind == b'data':
                break
            off += 8 + size + (size & 1)
        else:
            raise ValueError('No WAV data chunk')
        off += 8
        if off + size > len(mm):
            raise ValueError('Truncated WAV data chunk')

        state, pos = SEED, -1

        def next_byte():
            nonlocal state, pos
            value = 0
            for _ in range(8):
                state, draw = splitmix(state)
                pos += 1 + draw % 4096
                if pos >= size // 2:
                    raise ValueError('Carrier exhausted before frame was decoded')
                state, draw = splitmix(state)
                parity = (mm[off + 2 * pos] ^ ((draw >> 17) & 255)).bit_count() & 1
                value = (value << 1) | parity
            return value

        header = bytes(next_byte() for _ in range(16))
        assert header[:8] == b'MIRRORS1', 'Wrong seed or corrupt carrier'
        length, crc = struct.unpack('<II', header[8:])
        assert 0 < length < 100000
        payload = bytes(next_byte() for _ in range(length))
        assert zlib.crc32(payload) & 0xFFFFFFFF == crc, 'CRC mismatch'
        print(f'[+] Extracted {length} bytes (CRC OK)', flush=True)
        return payload


def run_vm(blob):
    assert blob[:4] == b'MVM1'
    clen, dlen, pc, _reserved = struct.unpack_from('<IIHH', blob, 4)
    assert clen <= 65536 and dlen <= 65536 and len(blob) == 16 + clen + dlen
    code, data = bytearray(65536), bytearray(65536)
    code[:clen] = blob[16:16 + clen]
    data[:dlen] = blob[16 + clen:]
    R, stack, output = [0] * 16, [], bytearray()
    R[15] = 0xCBF29CE484222325

    def b(addr):
        return code[addr & 65535]

    def w(addr):
        return b(addr) | (b(addr + 1) << 8)

    def q(addr):
        return sum(b(addr + i) << (8 * i) for i in range(8))

    for _step in range(2_000_000):
        op = b(pc)
        h = ((R[15] ^ op) * FNV) & MASK
        R[15] = h ^ (h >> 31)
        pair = b(pc + 1)
        rd, rs = pair >> 4, pair & 15

        if op == 0x0B:
            break
        elif op == 0x6E:
            pc += 1
        elif op == 0x3A:
            R[rs] = q(pc + 2); pc += 10
        elif op == 0xD1:
            R[rd] = R[rs]; pc += 2
        elif op == 0x39:
            R[rs] = (R[rs] << (b(pc + 2) & 63)) & MASK; pc += 3
        elif op == 0x8D:
            R[rs] >>= b(pc + 2) & 63; pc += 3
        elif op == 0x61:
            R[rs] = rol(R[rs], b(pc + 2)); pc += 3
        elif op == 0x7F:
            R[rd] = (R[rd] + R[rs]) & MASK; pc += 2
        elif op == 0xE3:
            R[rd] = (R[rd] - R[rs]) & MASK; pc += 2
        elif op == 0x12:
            R[rd] = (R[rd] * R[rs]) & MASK; pc += 2
        elif op == 0xA6:
            R[rd] ^= R[rs]; pc += 2
        elif op == 0x5B:
            R[rd] &= R[rs]; pc += 2
        elif op == 0xCC:
            R[rd] |= R[rs]; pc += 2
        elif op == 0x74:
            R[rs] = (~R[rs]) & MASK; pc += 2
        elif op == 0x95:
            R[rd] = data[R[rs] & 65535]; pc += 2
        elif op == 0x4C:
            data[R[rd] & 65535] = R[rs] & 255; pc += 2
        elif op == 0x27:
            R[rd] = sum(data[(R[rs] + i) & 65535] << (8 * i) for i in range(8))
            pc += 2
        elif op == 0xB8:
            for i in range(8):
                data[(R[rd] + i) & 65535] = (R[rs] >> (8 * i)) & 255
            pc += 2
        elif op == 0x6A:
            R[rd] = b(R[rs]); pc += 2
        elif op == 0xE8:
            code[R[rd] & 65535] = R[rs] & 255; pc += 2
        elif op == 0xF2:
            pc = w(pc + 1)
        elif op == 0x1D:
            pc = w(pc + 2) if R[rs] == 0 else pc + 4
        elif op == 0xC4:
            pc = w(pc + 2) if R[rs] != 0 else pc + 4
        elif op == 0x50:
            pc = w(pc + 2) if R[rd] < R[rs] else pc + 4
        elif op == 0x9A:
            assert len(stack) < 256
            stack.append((pc + 3) & 65535); pc = w(pc + 1)
        elif op == 0x2E:
            pc = stack.pop()
        elif op == 0xB3:
            output.append(R[rs] & 255); pc += 2
        elif op == 0x47:
            length = w(pc + 2) or 65536
            x = (R[rs] ^ R[15]) or GOLDEN
            for i in range(length):
                x ^= (x << 13) & MASK
                x ^= x >> 7
                x ^= (x << 17) & MASK
                x &= MASK
                code[(R[rd] + i) & 65535] ^= (x >> 24) & 255
            pc += 4
        else:
            raise ValueError(f'Unknown MVM1 opcode {op:02x} at {pc:04x}')
        pc &= 65535
        if len(output) > 100000:
            raise RuntimeError('Unexpectedly large VM output')
    else:
        raise RuntimeError('VM did not halt')

    assert output[:8] == b'MIRRORS1'
    print(f'[+] VM output: {len(output)} bytes', flush=True)
    return output


def parse_tlv(raw):
    assert raw[:8] == b'MIRRORS1'
    records, pos = {}, 8
    while pos < len(raw):
        typ = raw[pos]; pos += 1
        if typ == 0:
            break
        if pos + 2 > len(raw):
            raise ValueError('Truncated TLV header')
        length = struct.unpack_from('<H', raw, pos)[0]
        pos += 2
        if pos + length > len(raw):
            raise ValueError('Truncated TLV value')
        records.setdefault(typ, []).append(raw[pos:pos + length])
        pos += length
    return records


def recover_private(t):
    to_int = lambda x: int.from_bytes(x, 'big')
    n, L = to_int(t[1][0]), t[8][0][0]
    W, upper = 1 << L, 1 << (256 - L)
    sigs = [tuple(to_int(record[i:i + 32]) for i in (0, 32, 64)) for record in t[10]]
    assert len(sigs) == int.from_bytes(t[9][0], 'little')
    assert SECP256k1.order == n
    pub = t[7][0]
    qx, qy = to_int(pub[:32]), to_int(pub[32:])
    print(f'[+] ECDSA signatures: {len(sigs)}, L={L}', flush=True)

    for count in (26, 32, 40, len(sigs)):
        B = IntegerMatrix(count + 1, count + 1)
        target = []
        for i, (z, r, s) in enumerate(sigs[:count]):
            inv_s = pow(s, -1, n)
            B[i, i] = n * W
            B[count, i] = ((r * inv_s) % n) * W
            target.append((upper // 2 - (z * inv_s) % n) * W)
        B[count, count] = 1
        target.append(n // 2)
        LLL.reduction(B, delta=0.99)
        candidate = int(CVP.closest_vector(B, target)[-1]) % n
        Q = SECP256k1.generator * candidate
        if Q.x() == qx and Q.y() == qy:
            assert all(((z + r * candidate) * pow(s, -1, n)) % n < upper for z, r, s in sigs)
            print('[+] Private key recovered, Q=dG verified', flush=True)
            return candidate
    raise RuntimeError('Lattice attack failed')


def unseal(d, blob):
    state, key = 0x4D6972726F72734B, bytearray()
    for rnd in range(4):
        for v in d.to_bytes(32, 'big'):
            state = ((state ^ v) * FNV) & MASK
            state ^= state >> 29
            state = (state * GOLDEN) & MASK
            state ^= state >> 32
        state = (state + rnd * 0xFF51AFD7ED558CCD) & MASK
        key += state.to_bytes(8, 'big')

    a, b, c, e = struct.unpack('<4Q', key)
    counter, stream = 0, bytearray()
    while len(stream) < len(blob):
        counter = (counter + GOLDEN) & MASK
        e ^= counter
        for _ in range(4):
            a = (a + b) & MASK; e = rol(e ^ a, 32)
            c = (c + e) & MASK; b = rol(b ^ c, 24)
            a = (a + b) & MASK; e = rol(e ^ a, 16)
            c = (c + e) & MASK; b = rol(b ^ c, 37)
        stream += struct.pack('<Q', a ^ c)
    return bytes(x ^ y for x, y in zip(blob, stream))


def main():
    wav = sys.argv[1] if len(sys.argv) > 1 else 'hall-of-mirrors.wav'
    img = extract(wav)
    tlv = parse_tlv(run_vm(img))
    d = recover_private(tlv)
    flag = unseal(d, tlv[11][0])
    assert re.fullmatch(rb'hiCTF\{[^}]+\}', flag), repr(flag)
    print('[+] FLAG:', flag.decode())


if __name__ == '__main__':
    main()
