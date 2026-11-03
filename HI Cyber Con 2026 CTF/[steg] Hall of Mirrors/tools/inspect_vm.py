#!/usr/bin/env python3
"""Regenerate initial MVM1 bootstrap disassembly and the first SMC figure.

Run in the repository root after obtaining evidence/mirror_payload.bin:
    python3 tools/inspect_vm.py
Requires matplotlib/numpy only for the visualization.
"""
import struct
from pathlib import Path

MASK = (1 << 64) - 1
FNV = 0x100000001B3


def decode_bootstrap(code, entry):
    pc, lines = entry, []
    for _ in range(20):
        op = code[pc]
        if op == 0x3A:
            r = code[pc+1] & 15
            imm = int.from_bytes(code[pc+2:pc+10], 'little')
            lines.append(f'{pc:04X} IMM R{r}, 0x{imm:016X}')
            pc += 10
        elif op == 0x1D:
            r = code[pc+1] & 15
            target = int.from_bytes(code[pc+2:pc+4], 'little')
            lines.append(f'{pc:04X} JZ R{r}, 0x{target:04X}')
            pc += 4
        elif op == 0x47:
            pair = code[pc+1]
            length = int.from_bytes(code[pc+2:pc+4], 'little')
            lines.append(f'{pc:04X} SMC R{pair>>4}, R{pair&15}, length=0x{length:04X}')
            pc += 4
        elif op == 0xF2:
            target = int.from_bytes(code[pc+1:pc+3], 'little')
            lines.append(f'{pc:04X} JMP 0x{target:04X}')
            break
        else:
            lines.append(f'{pc:04X} UNKNOWN 0x{op:02X}')
            break
    return lines


def main():
    payload = Path('evidence/mirror_payload.bin').read_bytes()
    assert payload[:4] == b'MVM1'
    cl, dl, entry, _ = struct.unpack_from('<IIHH', payload, 4)
    assert len(payload) == 16+cl+dl
    code = bytearray(65536)
    code[:cl] = payload[16:16+cl]
    lines = [f'MVM1 — INITIAL BOOTSTRAP DISASSEMBLY',
             f'CODE={cl} bytes | DATA={dl} bytes | entry=0x{entry:04X}', '']
    lines += decode_bootstrap(code, entry)
    lines += ['', 'Static view only — SMC may change the code.']
    Path('evidence/hom_vm_bootstrap.txt').write_text('\n'.join(lines)+'\n')

    regs = [0]*16
    regs[15] = 0xCBF29CE484222325
    pc = entry
    while True:
        op = code[pc]
        h = ((regs[15]^op)*FNV)&MASK
        regs[15] = h^(h>>31)
        if op == 0x3A:
            regs[code[pc+1]&15] = int.from_bytes(code[pc+2:pc+10], 'little')
            pc += 10
        elif op == 0x1D:
            reg=code[pc+1]&15
            pc = int.from_bytes(code[pc+2:pc+4],'little') if regs[reg]==0 else pc+4
        elif op == 0x47:
            pair=code[pc+1]; rd,rs=pair>>4,pair&15
            length=int.from_bytes(code[pc+2:pc+4],'little') or 65536
            start=regs[rd]&65535
            before=bytes(code[(start+i)&65535] for i in range(length))
            seed=regs[rs]^regs[15]
            x=seed or 0x9E3779B97F4A7C15
            for i in range(length):
                x ^= (x<<13)&MASK
                x ^= x>>7
                x ^= (x<<17)&MASK
                x &= MASK
                code[(start+i)&65535] ^= (x>>24)&255
            after=bytes(code[(start+i)&65535] for i in range(length))
            Path('evidence/hom_smc_decrypted_region.bin').write_bytes(after)
            print(f'SMC PC=0x{pc:04X}, R15=0x{regs[15]:016X}, seed=0x{seed:016X}')
            print(f'target=0x{start:04X}, length={length}, modified={sum(a!=b for a,b in zip(before,after))}')
            break
        else:
            raise RuntimeError(f'Unexpected opcode {op:#x} at {pc:#x}')

    import numpy as np
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    assert length==256
    a=np.frombuffer(before,dtype=np.uint8).reshape(16,16)
    b=np.frombuffer(after,dtype=np.uint8).reshape(16,16)
    img=np.full((16,52),np.nan)
    img[:,0:16]=a;img[:,18:34]=b;img[:,36:52]=np.bitwise_xor(a,b)
    fig,ax=plt.subplots(figsize=(15,6))
    im=ax.imshow(img,interpolation='nearest',aspect='equal',vmin=0,vmax=255)
    ax.set_xticks([7.5,25.5,43.5],['BEFORE SMC','AFTER SMC','XOR DIFFERENCE'])
    ax.xaxis.tick_top()
    ax.set_yticks(list(range(0,16,2)),[f'{i*16:02X}' for i in range(0,16,2)])
    ax.set_ylabel('Relative byte offset')
    ax.set_title(f'Hall of Mirrors — Self-Modifying VM Code\nCODE 0x{start:04X}–0x{start+255:04X} | {sum(a!=b for a,b in zip(before,after))}/256 bytes changed',pad=35)
    fig.colorbar(im,ax=ax,label='Byte value (0–255)')
    fig.tight_layout()
    fig.savefig('assets/03_smc_before_after_regenerated.png',dpi=200,bbox_inches='tight')
    print('Wrote evidence/hom_vm_bootstrap.txt and assets/03_smc_before_after_regenerated.png')


if __name__=='__main__':
    main()
