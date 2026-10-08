"""Minimal NTAG 424 DNA and NTAG 21x simulators (written independently from the datasheet behaviour)
for testing without hardware. They implement only what ntag424_pcsc uses."""
import os
import struct
import zlib

from ntag424_pcsc import core as N


class Sim424:
    def __init__(self, uid=None):
        self.keys = [bytes(16)] * 5
        self.uid_b = uid or bytes.fromhex("04DE5F1EACC040")
        self.file = bytearray(256)
        self.access = (0xE, 0x0, 0xE, 0xE)       # RW, Change, Read, Write
        self.sdm = None
        self.read_ctr = 0
        self.app = False
        self.sel = None
        self.auth = None
        self.pending = None

    def transmit(self, apdu):
        a = bytes(apdu)
        cla, ins, p1, p2 = a[:4]
        if cla == 0xFF and ins == 0xCA:
            return list(self.uid_b), 0x90, 0x00
        if cla == 0x00 and ins == 0xA4:
            self.auth = None
            if p1 == 4:
                self.app = a[5:5 + a[4]] == N.NDEF_AID
                self.sel = None
                return [], 0x90, 0x00
            if p1 == 0 and self.app and a[5:7] == N.NDEF_FILE_ID:
                self.sel = 2
                if self.sdm:
                    self.read_ctr += 1
                return [], 0x90, 0x00
            return [], 0x6A, 0x82
        if cla == 0x00 and ins == 0xD6:
            if self.sel != 2 or self.access[3] != 0xE:
                return [], 0x69, 0x82
            off = (p1 << 8) | p2
            d = a[5:5 + a[4]]
            self.file[off:off + len(d)] = d
            return [], 0x90, 0x00
        if cla == 0x00 and ins == 0xB0:
            off = (p1 << 8) | p2
            return list(bytes(self._mirror()[off:off + a[4]])), 0x90, 0x00
        if cla == 0x90:
            return self._native(ins, a[5:5 + a[4]] if len(a) > 5 else b"")
        return [], 0x6D, 0x00

    def _mirror(self):
        f = bytearray(self.file)
        if self.sdm:
            k1, k2 = self.keys[self.sdm["meta"]], self.keys[self.sdm["fileread"]]
            ctr = struct.pack("<I", self.read_ctr)[:3]
            enc = N._cbc_enc(k1, bytes(16), bytes([0xC7]) + self.uid_b + ctr + os.urandom(5))
            f[self.sdm["picc"]:self.sdm["picc"] + 32] = enc.hex().upper().encode()
            ks = N.cmac(k2, b"\x3C\xC3\x00\x01\x00\x80" + self.uid_b + ctr)
            mac = N.cmac(ks, bytes(f[self.sdm["macin"]:self.sdm["mac"]]))[1::2]
            f[self.sdm["mac"]:self.sdm["mac"] + 16] = mac.hex().upper().encode()
        return f

    def _native(self, ins, data):
        if ins == 0x71:
            self.kno, self.rb, self.pending = data[0], os.urandom(16), "auth"
            return list(N._cbc_enc(self.keys[self.kno], bytes(16), self.rb)), 0x91, 0xAF
        if ins == 0xAF and self.pending == "auth":
            self.pending = None
            k = self.keys[self.kno]
            p = N._cbc_dec(k, bytes(16), data)
            if p[16:] != N._rotl(self.rb):
                return [], 0x91, 0xAE
            self.ti, self.cc = os.urandom(4), 0
            self.kenc, self.kmac = N.session_keys(k, p[:16], self.rb)
            self.auth = self.kno
            return list(N._cbc_enc(k, bytes(16), self.ti + N._rotl(p[:16]) + bytes(12))), 0x91, 0x00
        if ins in (0x5F, 0xC4) and self.auth is not None:
            hdr, enc, mac = data[:1], data[1:-8], data[-8:]
            if mac != N.mact(self.kmac, bytes([ins]) + struct.pack("<H", self.cc) + self.ti + hdr + enc):
                return [], 0x91, 0x1E
            iv = N._ecb(self.kenc, b"\xA5\x5A" + self.ti + struct.pack("<H", self.cc) + bytes(8))
            p = N._cbc_dec(self.kenc, iv, enc)
            p = p[:p.rindex(b"\x80")]
            self.cc += 1
            if ins == 0x5F:
                fo, ar0, ar1, so, sa0, sa1 = p[:6]
                assert hdr == b"\x02" and fo == 0x40 and so == 0xC1 and sa0 >> 4 == 0xF and len(p) == 15
                self.access = (ar0 >> 4, ar0 & 15, ar1 >> 4, ar1 & 15)
                o = [int.from_bytes(p[6 + 3 * i:9 + 3 * i], "little") for i in range(3)]
                self.sdm = dict(meta=sa1 >> 4, fileread=sa1 & 15, picc=o[0], macin=o[1], mac=o[2])
                self.read_ctr = 0
            else:
                kno = hdr[0]
                if kno == self.auth:
                    assert len(p) == 17
                    self.keys[kno], self.auth = p[:16], None
                    return [], 0x91, 0x00
                assert len(p) == 21
                new = bytes(x ^ y for x, y in zip(p[:16], self.keys[kno]))
                if p[17:21] != struct.pack("<I", zlib.crc32(new) ^ 0xFFFFFFFF):
                    return [], 0x91, 0x1E
                self.keys[kno] = new
            return list(N.mact(self.kmac, b"\x00" + struct.pack("<H", self.cc) + self.ti)), 0x91, 0x00
        return [], 0x91, 0x1C


class SimType2:
    """NTAG 213/215/216: OR-semantics on lock/CC pages, static lock bits for pages 3-15."""

    def __init__(self, cap=0x3E):
        self.mem = bytearray(4 * 135)
        self.mem[0:7] = os.urandom(7)
        self.mem[12:16] = bytes([0xE1, 0x10, cap, 0x00])

    def _locked(self, p):
        return (3 <= p <= 7 and self.mem[10] >> p & 1) or (8 <= p <= 15 and self.mem[11] >> (p - 8) & 1)

    def transmit(self, apdu):
        a = bytes(apdu)
        if a[:2] == b"\xFF\xCA":
            return list(self.mem[0:7]), 0x90, 0x00
        if a[:2] == b"\xFF\xB0":
            return list(self.mem[4 * a[3]:4 * a[3] + 16]), 0x90, 0x00
        if a[:2] == b"\xFF\xD6":
            p, d = a[3], a[5:9]
            if p < 2 or self._locked(p):
                return [], 0x63, 0x00
            if p == 2:
                self.mem[10] |= d[2]
                self.mem[11] |= d[3]
            elif p == 3:
                for i in range(4):
                    self.mem[12 + i] |= d[i]
            else:
                self.mem[4 * p:4 * p + 4] = d
            return [], 0x90, 0x00
        return [], 0x6A, 0x81
