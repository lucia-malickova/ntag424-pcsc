# ntag424-pcsc

Program **NXP NTAG 424 DNA** (SUN / Secure Dynamic Messaging with your own AES keys) and
**NTAG 213 / 215 / 216** with an ordinary USB NFC reader such as the **ACS ACR1252U**.
Pure Python, no proprietary tools, works on macOS, Windows and Linux.

Built by [Modelos Inteligencia Artificial S.L.](https://www.modelosia.es) for the NFC tokens of
our AI twins (MIA). We needed to configure tags in batches without TagXplorer or a phone app, so we
wrote this and made it free for everyone.

> **Status: beta (0.1).** The full flow is tested against the tag simulator in `tests/`, which follows
> NXP NT4H2421Gx and AN12196. Hardware testing on real tags is in progress.
> Please [open an issue](../../issues) with your reader model and the result.

## What it does

| Tag | What you get |
|---|---|
| NTAG 424 DNA | Writes your URL, enables **SUN**: on every tap the tag appends a fresh encrypted UID + counter (`{PICC}`) and a signature (`{CMAC}`), so a copied link stops working. Sets your own keys. Verifies itself after writing. |
| NTAG 213/215/216 | Writes a URL, reads it back, and can **lock** the tag permanently so nobody can overwrite it with a phone app. |
| Batch mode | Place tags one after another, no keyboard needed. |

## Install

```bash
pip install cryptography pyscard
git clone https://github.com/lucia-malickova/ntag424-pcsc
cd ntag424-pcsc
```

- **macOS:** the reader works with the built-in driver. Plug it into the computer that runs the
  script (not into a machine you only use for remote access).
- **Windows:** install the reader driver from the vendor (for ACR1252U: acs.com.hk).
- **Linux:** `sudo apt install pcscd libpcsclite-dev` and start `pcscd`.

Check that the reader is visible:
```bash
python -c "from smartcard.System import readers; print(readers())"
# ['ACS ACR1252 Dual Reader PICC', 'ACS ACR1252 Dual Reader SAM']
```

## Command line

```bash
python -m ntag424_pcsc info                                   # tag type, UID, current URL, lock state
python -m ntag424_pcsc write https://example.com/hi           # plain URL (213/215/216 or 424)
python -m ntag424_pcsc write https://example.com/hi --lock --batch   # many tags, locked (permanent!)

python -m ntag424_pcsc genkeys keys.json                      # random AES keys, file mode 600
python -m ntag424_pcsc sun "https://example.com/tap?p={PICC}&c={CMAC}" --keys keys.json --batch
python -m ntag424_pcsc verify --picc <32 hex> --cmac <16 hex> --keys keys.json
```

`sun` only touches **factory-new** NTAG 424 DNA tags (key 0 = 00…00). It writes the URL, enables SUN
(PICC data encrypted with key 1, CMAC with key 2, file readable by anyone, writable and
reconfigurable only with key 0), changes keys 1, 2 and finally key 0, then reads the tag and
verifies the signature. A tag that already has custom keys is left untouched.

> **Keep `keys.json` secret and backed up.** Without it you cannot verify taps or reconfigure your tags.
> Never commit it (it is in `.gitignore`).

## Python API

```python
from ntag424_pcsc import connect, verify_sun

tag, reader = connect()
if tag.is_424():
    url = tag.setup_sun("https://example.com/tap?p={PICC}&c={CMAC}",
                        {"key0": k0, "key1": k1, "key2": k2})        # 16-byte keys
else:
    tag.write_url_type2("https://example.com/hi", lock=False)

# on your server, for every tap:
r = verify_sun(picc_hex, cmac_hex, meta_key=k1, file_key=k2)
if r:
    uid, counter = r      # reject counters you have already seen -> copied links stop working
```

## Tests (no reader needed)

```bash
python tests/test_simulated.py      # or: python -m pytest tests
```

## Notes

- **Locking an NTAG 21x is permanent.** `--lock` sets the capability container to read-only and the static
  lock bits for pages 3-15 (record header, domain and the start of the URL).
- The reader must support ISO 14443-4 APDU pass-through (all common PC/SC NFC readers do) and the
  PC/SC pseudo-APDUs `FF B0` / `FF D6` / `FF CA` for NTAG 21x.
- Byte layouts were cross-checked with NXP AN12196, [Proxmark3](https://github.com/RfidResearchGroup/proxmark3)
  and [MFRC522_NTAG424DNA](https://github.com/obsttube/mfrc522_ntag424dna). Thank you!

## License

MIT © 2026 Modelos Inteligencia Artificial S.L. Use it, change it, ship it. No warranty.
