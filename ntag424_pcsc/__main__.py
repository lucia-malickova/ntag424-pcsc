"""Command line: python -m ntag424_pcsc <command> ...

  info                                   reader, tag type, UID and current URL
  write  <url> [--lock] [--batch]        write a plain URL (NTAG 213/215/216 or 424 DNA); --lock = permanent (21x)
  genkeys <keys.json>                    create random AES keys for SUN (keep this file secret!)
  sun    <url-template> --keys k.json [--batch]
                                         configure factory-new NTAG 424 DNA tags for SUN, e.g.
                                         "https://example.com/tap?p={PICC}&c={CMAC}"
  verify --picc <hex> --cmac <hex> --keys k.json
                                         check a tapped URL (prints UID and read counter)
"""
import argparse
import json
import os
import sys
from urllib.parse import urlparse, parse_qs

from .core import TagError, ndef_file, read_uri, verify_sun
from .reader import connect


def load_keys(path):
    with open(path) as f:
        k = json.load(f)
    return {n: bytes.fromhex(k[n]) for n in ("key0", "key1", "key2")}


def one_tag(args, first):
    tag, _ = connect(timeout=600 if args.batch else 30, new=not first, reader=args.reader)
    return tag


def cmd_info(args):
    tag, reader = connect(timeout=30, reader=args.reader)
    print(f"reader: {reader}")
    print(f"UID:    {tag.uid()}")
    if tag.is_424():
        print("type:   NTAG 424 DNA")
        print(f"URL:    {read_uri(tag.read_ndef_424(), with_nlen=False) or '(none)'}")
        tag.select_ndef_app()
        s = tag.authenticate(0, bytes(16))
        print("keys:   factory (00..00)" if s else "keys:   custom (key 0 is not factory)")
    else:
        cc = tag._read_pages(3)[:4]
        print(f"type:   NFC Type 2 ({ {0x12: 'NTAG213', 0x3E: 'NTAG215', 0x6D: 'NTAG216'}.get(cc[2], hex(cc[2])) })")
        print(f"URL:    {tag.read_url_type2() or '(none)'}")
        print(f"locked: {'yes' if cc[3] & 0x0F else 'no'}")


def loop(args, fn):
    done, first = 0, True
    if args.batch:
        print("Batch mode: place tags one after another, Ctrl+C to stop.")
    while True:
        try:
            tag = one_tag(args, first)
            first = False
            print(f"OK  {fn(tag)}")
            done += 1
        except KeyboardInterrupt:
            break
        except TagError as e:
            print(f"ERR {e}")
            if not args.batch or "reader" in str(e):
                break
        except Exception as e:
            print(f"ERR {type(e).__name__}: {e} - remove the tag and place it again")
            if not args.batch:
                break
        if not args.batch:
            break
    print(f"done: {done}")


def cmd_write(args):
    def fn(tag):
        uid = tag.uid()
        if tag.is_424():
            tag.write_ndef_424(ndef_file(args.url))
            tag.select_ndef_app()
            if read_uri(tag.read_ndef_424(), with_nlen=False) != args.url:
                raise TagError("read-back check failed")
            return f"{uid} NTAG 424 DNA written (plain URL, no SUN)"
        return f"{uid} {tag.write_url_type2(args.url, lock=args.lock)}"
    loop(args, fn)


def cmd_genkeys(args):
    if os.path.exists(args.path):
        sys.exit(f"{args.path} exists - refusing to overwrite (tags configured with it would become unusable)")
    fd = os.open(args.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({n: os.urandom(16).hex() for n in ("key0", "key1", "key2")}, f, indent=1)
    print(f"created {args.path} (mode 600). BACK IT UP and never commit it: without it your tags cannot be verified.")


def cmd_sun(args):
    keys = load_keys(args.keys)

    def fn(tag):
        url = tag.setup_sun(args.template, keys)
        q = parse_qs(urlparse(url).query)
        vals = [v[0] for v in q.values() if v and len(v[0]) in (32, 16)]
        picc = next((v for v in vals if len(v) == 32), "")
        mac = next((v for v in vals if len(v) == 16), "")
        r = verify_sun(picc, mac, keys["key1"], keys["key2"])
        if not r:
            raise TagError(f"tag configured but self-check failed - keep this tag aside ({url})")
        return f"{r[0]} SUN configured and verified (counter {r[1]})"
    loop(args, fn)


def cmd_verify(args):
    keys = load_keys(args.keys)
    r = verify_sun(args.picc, args.cmac, keys["key1"], keys["key2"])
    print(f"valid - UID {r[0]}, read counter {r[1]}" if r else "INVALID")
    sys.exit(0 if r else 1)


def main(argv=None):
    p = argparse.ArgumentParser(prog="python -m ntag424_pcsc", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--reader", help="part of the reader name to use (default: first contactless reader)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("info")
    w = sub.add_parser("write"); w.add_argument("url"); w.add_argument("--lock", action="store_true"); w.add_argument("--batch", action="store_true")
    g = sub.add_parser("genkeys"); g.add_argument("path")
    s = sub.add_parser("sun"); s.add_argument("template"); s.add_argument("--keys", required=True); s.add_argument("--batch", action="store_true")
    v = sub.add_parser("verify"); v.add_argument("--picc", required=True); v.add_argument("--cmac", required=True); v.add_argument("--keys", required=True)
    args = p.parse_args(argv)
    try:
        {"info": cmd_info, "write": cmd_write, "genkeys": cmd_genkeys, "sun": cmd_sun, "verify": cmd_verify}[args.cmd](args)
    except TagError as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
