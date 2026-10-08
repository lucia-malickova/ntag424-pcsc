"""Program NXP NTAG 424 DNA (SUN / SDM with your own AES keys) and NTAG 213/215/216 with a PC/SC reader."""
from .core import (Tag, Session, TagError, FACTORY_KEY, sdm_template, sdm_file_settings, ndef_file,
                   verify_sun, session_keys, read_uri)
from .reader import connect

__version__ = "0.1.0"
__all__ = ["Tag", "Session", "TagError", "FACTORY_KEY", "sdm_template", "sdm_file_settings", "ndef_file",
           "verify_sun", "session_keys", "read_uri", "connect"]
