"""PC/SC reader access (pyscard). Tested target: ACS ACR1252U; any PC/SC NFC reader should work."""
from .core import Tag, TagError


def connect(timeout=30, new=False, reader=None):
    """Wait for a tag and return (Tag, reader_name). new=True waits for the NEXT tag (previous removed)."""
    try:
        from smartcard.System import readers
        from smartcard.CardRequest import CardRequest
        from smartcard.CardType import AnyCardType
        from smartcard.Exceptions import CardRequestTimeoutException
    except ImportError:
        raise TagError("pyscard is missing: pip install pyscard")
    rs = readers()
    if not rs:
        raise TagError("no PC/SC reader found - is it plugged into THIS computer?")
    if reader:
        rs = [r for r in rs if reader.lower() in str(r).lower()] or rs
    # dual readers (e.g. ACR1252U) expose a contactless "PICC" slot and a "SAM" slot
    picc = [r for r in rs if "PICC" in str(r).upper()] or [r for r in rs if "SAM" not in str(r).upper()] or rs
    try:
        svc = CardRequest(timeout=timeout, readers=[picc[0]], cardType=AnyCardType(), newcardonly=new).waitforcard()
    except CardRequestTimeoutException:
        raise TagError("no tag on the reader")
    svc.connection.connect()
    return Tag(svc.connection), str(picc[0])
