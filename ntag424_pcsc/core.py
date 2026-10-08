"""NTAG 424 DNA and NTAG 213/215/216 over any PC/SC reader.

Crypto follows NXP NT4H2421Gx / AN12196 (AuthenticateEV2First, CommMode.Full secure messaging,
ChangeFileSettings with SDM/SUN, ChangeKey). All reader I/O goes through an object with a
pyscard-style ``transmit(list) -> (data, sw1, sw2)`` method, so the same code runs against a real
reader or the simulator in ``tests/``.
"""
import os
import struct
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC

NDEF_AID = bytes.fromhex("D2760000850101")
NDEF_FILE_ID = bytes.fromhex("E104")
FACTORY_KEY = bytes(16)
PICC_PLACEHOLDER = "{PICC}"   # 32 hex chars: encrypted UID + read counter
CMAC_PLACEHOLDER = "{CMAC}"   # 16 hex chars: SUN signature


class TagError(Exception):
    pass


# ---------------------------------------------------------------- crypto helpers
def _ecb(key, data):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(data) + e.finalize()


def _cbc_enc(key, iv, data):
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()


def _cbc_dec(key, iv, data):
    d = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return d.update(data) + d.finalize()


def cmac(key, data):
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def mact(key, data):
    """Truncated MAC used by NTAG 424: the odd bytes (1, 3, ... 15) of the AES-CMAC."""
    return cmac(key, data)[1::2]


def _pad(data):
    data = data + b"\x80"
    return data + bytes(-len(data) % 16)


def _rotl(b):
    return b[1:] + b[:1]


def crc32nk(key):
    """CRC32 of the new key as ChangeKey expects it (JAMCRC, little endian)."""
    return struct.pack("<I", zlib.crc32(key) ^ 0xFFFFFFFF)


def session_keys(kx, rnd_a, rnd_b):
    """(KSesAuthENC, KSesAuthMAC) derived from SV1 / SV2 after AuthenticateEV2First."""
    x = bytes(a ^ b for a, b in zip(rnd_a[2:8], rnd_b[0:6]))
    tail = rnd_a[0:2] + x + rnd_b[6:16] + rnd_a[8:16]
    return cmac(kx, b"\xA5\x5A\x00\x01\x00\x80" + tail), cmac(kx, b"\x5A\xA5\x00\x01\x00\x80" + tail)


# ---------------------------------------------------------------- NDEF / SDM layout
def _split_scheme(url):
    if url.startswith("https://"):
        return 0x04, url[8:]
    if url.startswith("http://"):
        return 0x03, url[7:]
    return 0x00, url


def ndef_file(url):
    """NDEF file content: NLEN (2 bytes) + one short URI record."""
    prefix, rest = _split_scheme(url)
    u = rest.encode()
    if len(u) + 1 > 255:
        raise TagError("URL too long for a short NDEF record")
    rec = bytes([0xD1, 0x01, len(u) + 1, 0x55, prefix]) + u
    return struct.pack(">H", len(rec)) + rec


def sdm_template(url):
    """Turn a URL with {PICC} and {CMAC} placeholders into (url_with_zeros, offsets).

    Offsets are positions inside the NDEF file (2-byte NLEN + 5-byte record header + URL)."""
    if PICC_PLACEHOLDER not in url or CMAC_PLACEHOLDER not in url:
        raise TagError("URL must contain {PICC} and {CMAC}, e.g. https://example.com/tap?p={PICC}&c={CMAC}")
    _, rest = _split_scheme(url)
    picc = 7 + rest.index(PICC_PLACEHOLDER)
    zeros = rest.replace(PICC_PLACEHOLDER, "0" * 32)
    mac = 7 + zeros.index(CMAC_PLACEHOLDER)
    full = url.replace(PICC_PLACEHOLDER, "0" * 32).replace(CMAC_PLACEHOLDER, "0" * 16)
    return full, {"PICCDataOffset": picc, "SDMMACInputOffset": mac, "SDMMACOffset": mac}


def sdm_file_settings(offsets, meta_key=1, file_key=2):
    """ChangeFileSettings data for file 02 with SUN enabled.

    FileOption 0x40 (SDM on, plain), AccessRights 00 E0 (RW key0, Change key0, Read free, Write key0),
    SDMOptions C1 (UID + read counter mirror, ASCII), SDMAccessRights F F | meta file
    (RFU, CtrRet none, SDMMetaRead = meta_key -> encrypted PICC data, SDMFileRead = file_key -> CMAC)."""
    o3 = lambda v: struct.pack("<I", v)[:3]
    return (b"\x40" + b"\x00\xE0" + b"\xC1" + b"\xFF" + bytes([(meta_key << 4) | file_key])
            + o3(offsets["PICCDataOffset"]) + o3(offsets["SDMMACInputOffset"]) + o3(offsets["SDMMACOffset"]))


# ---------------------------------------------------------------- SUN verification (server side)
def verify_sun(picc_hex, cmac_hex, meta_key, file_key):
    """Check a tapped URL. Returns (uid_hex, read_counter) or None if invalid.

    Works for the configuration written by ``setup_sun`` (MAC over an empty input, i.e.
    SDMMACInputOffset == SDMMACOffset). Remember to reject counters you have already seen."""
    try:
        if len(picc_hex) != 32 or len(cmac_hex) != 16:
            return None
        p = _cbc_dec(meta_key, bytes(16), bytes.fromhex(picc_hex))
        if p[0] & 0x80 == 0 or p[0] & 0x40 == 0 or p[0] & 0x0F != 7:
            return None
        uid, ctr = p[1:8], p[8:11]
        ks = cmac(file_key, b"\x3C\xC3\x00\x01\x00\x80" + uid + ctr)
        if cmac(ks, b"")[1::2] != bytes.fromhex(cmac_hex):
            return None
        return uid.hex().upper(), int.from_bytes(ctr, "little")
    except ValueError:
        return None


# ---------------------------------------------------------------- tag access
class Session:
    """Authenticated EV2 session (CommMode.Full commands)."""

    def __init__(self, tag, kenc, kmac, ti):
        self.tag, self.kenc, self.kmac, self.ti, self.ctr = tag, kenc, kmac, ti, 0

    def _iv(self, prefix):
        return _ecb(self.kenc, prefix + self.ti + struct.pack("<H", self.ctr) + bytes(8))

    def full(self, cmd, header, data, expect_mac=True):
        enc = _cbc_enc(self.kenc, self._iv(b"\xA5\x5A"), _pad(data))
        mac = mact(self.kmac, bytes([cmd]) + struct.pack("<H", self.ctr) + self.ti + header + enc)
        resp, sw = self.tag.native(cmd, header + enc + mac)
        if sw != 0x9100:
            raise TagError(f"command {cmd:02X} rejected (SW {sw:04X})")
        self.ctr += 1
        if expect_mac:
            want = mact(self.kmac, b"\x00" + struct.pack("<H", self.ctr) + self.ti + resp[:-8])
            if resp[-8:] != want:
                raise TagError(f"command {cmd:02X}: response MAC mismatch")
        return resp

    def change_file_settings(self, file_no, settings):
        self.full(0x5F, bytes([file_no]), settings)

    def change_key(self, key_no, new_key, old_key=FACTORY_KEY, version=1):
        """Change key ``key_no``. Changing the key you authenticated with ends the session."""
        if key_no == 0:
            self.full(0xC4, b"\x00", new_key + bytes([version]), expect_mac=False)
        else:
            x = bytes(a ^ b for a, b in zip(new_key, old_key))
            self.full(0xC4, bytes([key_no]), x + bytes([version]) + crc32nk(new_key))


class Tag:
    """A tag on the reader. ``conn`` needs a pyscard-style ``transmit``."""

    def __init__(self, conn):
        self.conn = conn

    def apdu(self, a):
        data, sw1, sw2 = self.conn.transmit(list(a))
        return bytes(data), (sw1 << 8) | sw2

    def native(self, cmd, data=b""):
        return self.apdu(bytes([0x90, cmd, 0, 0]) + (bytes([len(data)]) + data if data else b"") + b"\x00")

    def uid(self):
        r, sw = self.apdu(b"\xFF\xCA\x00\x00\x00")
        return r.hex().upper() if sw == 0x9000 else None

    # ---- NTAG 424 DNA
    def is_424(self):
        try:
            self.select_ndef_app()
            return True
        except TagError:
            return False

    def select_ndef_app(self):
        r, sw = self.apdu(b"\x00\xA4\x04\x0C" + bytes([len(NDEF_AID)]) + NDEF_AID + b"\x00")
        if sw != 0x9000:
            raise TagError(f"not an NTAG 424 DNA (select application: SW {sw:04X})")

    def select_ndef_file(self):
        r, sw = self.apdu(b"\x00\xA4\x00\x0C\x02" + NDEF_FILE_ID)
        if sw != 0x9000:
            raise TagError(f"cannot select NDEF file (SW {sw:04X})")

    def write_ndef_424(self, content):
        self.select_ndef_file()
        r, sw = self.apdu(b"\x00\xD6\x00\x00" + bytes([len(content)]) + content)
        if sw != 0x9000:
            raise TagError(f"NDEF write rejected (SW {sw:04X}) - tag already configured?")

    def read_ndef_424(self):
        self.select_ndef_file()
        head, sw = self.apdu(b"\x00\xB0\x00\x00\x02")
        if sw != 0x9000:
            raise TagError(f"read failed (SW {sw:04X})")
        n = struct.unpack(">H", head)[0]
        body, sw = self.apdu(b"\x00\xB0\x00\x02" + bytes([n]))
        if sw != 0x9000:
            raise TagError(f"read failed (SW {sw:04X})")
        return body

    def authenticate(self, key_no, key):
        """AuthenticateEV2First. Returns a Session, or None if the key is wrong."""
        r, sw = self.native(0x71, bytes([key_no, 0x00]))
        if sw != 0x91AF or len(r) != 16:
            raise TagError(f"authentication did not start (SW {sw:04X})")
        rnd_b = _cbc_dec(key, bytes(16), r)
        rnd_a = os.urandom(16)
        r, sw = self.native(0xAF, _cbc_enc(key, bytes(16), rnd_a + _rotl(rnd_b)))
        if sw != 0x9100:
            return None
        p = _cbc_dec(key, bytes(16), r)
        if p[4:20] != _rotl(rnd_a):
            raise TagError("tag returned a wrong authentication response")
        kenc, kmac = session_keys(key, rnd_a, rnd_b)
        return Session(self, kenc, kmac, p[0:4])

    def setup_sun(self, url_template, keys):
        """Configure a FACTORY-NEW NTAG 424 DNA for SUN.

        url_template: e.g. "https://example.com/tap?p={PICC}&c={CMAC}"
        keys: {"key0": 16 bytes (app master), "key1": (SDM meta read), "key2": (SDM file read / CMAC)}
        Returns the URL as read back from the tag (with live PICC and CMAC values)."""
        url, offsets = sdm_template(url_template)
        self.select_ndef_app()
        if self.authenticate(0, FACTORY_KEY) is None:
            raise TagError("tag does not have factory keys - nothing changed")
        self.select_ndef_app()                       # selecting a file drops authentication -> write first
        self.write_ndef_424(ndef_file(url))
        self.select_ndef_app()
        s = self.authenticate(0, FACTORY_KEY)
        s.change_file_settings(2, sdm_file_settings(offsets))
        s.change_key(1, keys["key1"])
        s.change_key(2, keys["key2"])
        s.change_key(0, keys["key0"])                # last: afterwards only your keys work
        self.select_ndef_app()
        return read_uri(self.read_ndef_424(), with_nlen=False)

    # ---- NTAG 213 / 215 / 216 (NFC Forum Type 2)
    def _read_pages(self, page):
        r, sw = self.apdu(bytes([0xFF, 0xB0, 0x00, page, 0x10]))
        if sw != 0x9000 or len(r) < 16:
            raise TagError(f"cannot read tag (SW {sw:04X})")
        return r[:16]

    def read_url_type2(self):
        d = b"".join(self._read_pages(p) for p in (4, 8, 12, 16, 20, 24))
        if d[0] != 0x03 or d[1] < 5:
            return ""
        return read_uri(d[2:2 + d[1]], with_nlen=False)

    def write_url_type2(self, url, lock=False):
        """Write a URL to an NTAG 213/215/216, verify it, optionally make the tag read-only.

        lock=True is PERMANENT: CC is set to read-only and static lock bits for pages 3-15
        (record header, domain and the start of the URL) are set."""
        cc = self._read_pages(3)[:4]
        if cc[0] != 0xE1:
            raise TagError("tag is not NDEF formatted (no capability container)")
        if cc[3] & 0x0F:
            if self.read_url_type2() == url:
                return "already written and locked"
            raise TagError("tag is locked and holds a different URL")
        f = ndef_file(url)[2:]
        tlv = bytes([0x03, len(f)]) + f + b"\xFE"
        if len(tlv) > cc[2] * 8:
            raise TagError("URL does not fit on this tag")
        tlv += bytes(-len(tlv) % 4)
        for i in range(0, len(tlv), 4):
            r, sw = self.apdu(bytes([0xFF, 0xD6, 0x00, 4 + i // 4, 0x04]) + tlv[i:i + 4])
            if sw != 0x9000:
                raise TagError(f"write rejected (SW {sw:04X})")
        if self.read_url_type2() != url:
            raise TagError("read-back check failed - place the tag again")
        if not lock:
            return "written"
        r, sw = self.apdu(bytes([0xFF, 0xD6, 0x00, 0x03, 0x04]) + cc[:3] + b"\x0F")
        p2 = self._read_pages(2)[:4]
        r2, sw2 = self.apdu(bytes([0xFF, 0xD6, 0x00, 0x02, 0x04]) + p2[:2] + b"\xFF\xFF")
        if sw != 0x9000 or sw2 != 0x9000 or self._read_pages(2)[2:4] != b"\xFF\xFF" or self._read_pages(3)[3] != 0x0F:
            raise TagError("URL written, but locking failed")
        return "written and locked"


URI_PREFIX = {0x00: "", 0x01: "http://www.", 0x02: "https://www.", 0x03: "http://", 0x04: "https://"}


def read_uri(data, with_nlen=True):
    """Parse the first URI record of an NDEF message."""
    if with_nlen:
        data = data[2:] if len(data) > 2 and data[0] == 0 else data
    if len(data) < 5 or data[0] != 0xD1 or data[3] != 0x55:
        return ""
    return URI_PREFIX.get(data[4], "") + data[5:4 + data[2]].decode(errors="replace")
