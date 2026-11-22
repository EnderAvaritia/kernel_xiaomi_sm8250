import struct, hashlib, gzip, sys

SRC = 'mipad5pro_boot.img'
KSRC = 'Image'
OUT = 'mipad5pro_boot_nova.img'
PAGE = 4096
PART = 134217728

st = open(SRC, 'rb').read()
k = open(KSRC, 'rb').read()
assert st[:8] == b'ANDROID!' and k[0x38:0x3c] == b'ARMd', 'bad input'

ks_old, rs = struct.unpack('<2I', st[8:16])
roff = PAGE + ((ks_old + PAGE - 1) // PAGE) * PAGE
ramdisk = st[roff:roff + rs]
assert gzip.decompress(ramdisk)                       # ramdisk 必须可解压
assert struct.unpack('<I', st[40:44])[0] == 3         # header v3
assert struct.unpack('<I', st[20:24])[0] == 1580

AVB_OFF = st.find(b'AVB0')
AVB_SIZE = 896
assert AVB_OFF > 0 and st[AVB_OFF:AVB_OFF + 4] == b'AVB0'
assert st[AVB_OFF + 128:AVB_OFF + 140].startswith(b'avbtool')

vbmeta = bytearray(st[AVB_OFF:AVB_OFF + AVB_SIZE])
vbmeta[120:124] = struct.pack('>I', 3)                # 关 verity + 签名校验

hdr = bytearray(st[:1580])
hdr[8:12] = struct.pack('<I', len(k))

al = lambda x: (x + PAGE - 1) // PAGE * PAGE
content = bytes(hdr).ljust(PAGE, b'\0')
content += k.ljust(al(len(k)), b'\0')
content += ramdisk.ljust(al(rs), b'\0')
S = len(content)
assert S % PAGE == 0 and S + AVB_SIZE <= PART - 64

img = bytearray(content) + vbmeta
img += b'\0' * (PART - 64 - len(img))
ft = bytearray(64)
ft[0:4] = b'AVBf'
struct.pack_into('>I', ft, 4, 1)
struct.pack_into('>I', ft, 8, 0)
struct.pack_into('>Q', ft, 12, S)
struct.pack_into('>Q', ft, 20, S)
struct.pack_into('>Q', ft, 28, AVB_SIZE)
img += ft
assert len(img) == PART
open(OUT, 'wb').write(img)

# ---------- verify ----------
v = open(OUT, 'rb').read()
ks2, rs2 = struct.unpack('<2I', v[8:16])
k2 = v[PAGE:PAGE + ks2]
rd2 = v[PAGE + al(ks2):PAGE + al(ks2) + rs2]
assert k2 == k, 'kernel mismatch'
assert hashlib.sha256(rd2).digest() == hashlib.sha256(ramdisk).digest(), 'ramdisk mismatch'
assert len(gzip.decompress(rd2)) == len(gzip.decompress(ramdisk))
assert v[S:S + 4] == b'AVB0' and struct.unpack('>I', v[S + 120:S + 124])[0] == 3
assert v[-64:-60] == b'AVBf'
assert struct.unpack('>Q', v[-52:-44])[0] == S
print('OK', OUT, len(v))
print('kernel', len(k), 'ramdisk', rs2, 'content', S)
print('sha256', hashlib.sha256(v).hexdigest())