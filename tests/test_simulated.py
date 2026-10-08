"""Run: python -m pytest tests   (or: python tests/test_simulated.py)"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from urllib.parse import urlparse, parse_qs

from ntag424_pcsc import Tag, TagError, verify_sun, sdm_template
from simulator import Sim424, SimType2

KEYS = {"key0": bytes(range(16)), "key1": bytes(range(16, 32)), "key2": bytes(range(32, 48))}
TEMPLATE = "https://example.com/tap?p={PICC}&c={CMAC}"


def _params(url):
    q = parse_qs(urlparse(url).query)
    return q["p"][0], q["c"][0]


def test_sun_setup_and_verify():
    sim = Sim424()
    tag = Tag(sim)
    url = tag.setup_sun(TEMPLATE, KEYS)
    uid, ctr = verify_sun(*_params(url), KEYS["key1"], KEYS["key2"])
    assert uid == "04DE5F1EACC040"
    assert sim.keys[:3] == [KEYS["key0"], KEYS["key1"], KEYS["key2"]]
    assert sim.access == (0, 0, 0xE, 0)


def test_sun_counter_increases_and_wrong_keys_fail():
    sim = Sim424()
    tag = Tag(sim)
    u1 = tag.setup_sun(TEMPLATE, KEYS)
    tag.select_ndef_app()
    from ntag424_pcsc import read_uri
    u2 = read_uri(tag.read_ndef_424(), with_nlen=False)
    c1 = verify_sun(*_params(u1), KEYS["key1"], KEYS["key2"])[1]
    c2 = verify_sun(*_params(u2), KEYS["key1"], KEYS["key2"])[1]
    assert c2 > c1 and u1 != u2
    assert verify_sun(*_params(u2), KEYS["key2"], KEYS["key1"]) is None


def test_configured_tag_is_not_touched_again():
    sim = Sim424()
    Tag(sim).setup_sun(TEMPLATE, KEYS)
    try:
        Tag(sim).setup_sun(TEMPLATE, {k: bytes(16) for k in KEYS})
        assert False, "should refuse"
    except TagError:
        pass
    assert sim.keys[0] == KEYS["key0"]


def test_template_offsets():
    url, off = sdm_template(TEMPLATE)
    assert url == "https://example.com/tap?p=" + "0" * 32 + "&c=" + "0" * 16
    assert off["PICCDataOffset"] == 7 + len("example.com/tap?p=")
    assert off["SDMMACOffset"] == off["SDMMACInputOffset"] == 7 + len("example.com/tap?p=") + 32 + len("&c=")


def test_type2_write_and_lock():
    sim = SimType2()
    tag = Tag(sim)
    assert tag.write_url_type2("https://example.com/hello", lock=True) == "written and locked"
    assert tag.read_url_type2() == "https://example.com/hello"
    assert sim.mem[10:12] == b"\xFF\xFF" and sim.mem[15] == 0x0F
    try:
        tag.write_url_type2("https://evil.example/x")
        assert False, "locked tag must refuse"
    except TagError:
        pass
    assert tag.write_url_type2("https://example.com/hello", lock=True) == "already written and locked"


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
