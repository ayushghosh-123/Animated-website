import locale
from typing import Tuple, Optional

import lldb
from renderers.jb_lldb_declarative_formatters_options import get_max_string_length


def get_max_string_summary_length(debugger):
    debugger_name = debugger.GetInstanceName()
    max_len = lldb.SBDebugger.GetInternalVariableValue("target.max-string-summary-length", debugger_name)
    return int(max_len.GetStringAtIndex(0))


_char_codes = {0: "\\0", 7: "\\a", 8: "\\b", 9: "\\t", 10: "\\n", 11: "\\v", 12: "\\f", 13: "\\r"}


def _repr(c):
    char_code = ord(c)
    if char_code >= 0 and (char_code < 0x1f or char_code == 0x7f):
        if char_code in _char_codes:
            return _char_codes[char_code]
        else:
            return "\\x" + format(char_code, 'x')
    else:
        return c


_locale = locale.getdefaultlocale()[1]


def override_locale(loc_name):
    global _locale
    _locale = loc_name


def get_locale():
    return _locale


def escape_char(char_code, char_size, enc):
    b: bytes = char_code.to_bytes(char_size, 'little')
    return escape_bytes(b, enc)


def escape_bytes(b, enc):
    s = b.decode(enc, 'replace')
    s = ''.join([_repr(c) for c in s])
    return s


def extract_string(process: lldb.SBProcess, address, char_size, max_size, err) -> Tuple[Optional[bytes], bool]:
    if max_size is None:
        max_size = char_size * get_max_string_length()
    max_size = min(max_size, char_size * get_max_string_length())

    zero = b'\x00' * char_size
    result = bytearray()
    read_bytes = 0
    zero_found = False
    while read_bytes < max_size:
        content = process.ReadMemory(address, char_size, err)
        if err.Fail():
            return None, zero_found
        if content == zero:
            zero_found = True
            break
        result += content
        address += char_size
        read_bytes += char_size

    return bytes(result), zero_found
