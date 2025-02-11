import lldb
from jb_declarative_formatters import TypeVizFormatSpec, TypeVizFormatFlags

# @formatter:off
eFormatHexNoPrefix              = lldb.kNumFormats + 1
eFormatHexUppercaseNoPrefix     = lldb.kNumFormats + 2
eFormatBinaryNoPrefix           = lldb.kNumFormats + 3
eFormatCStringNoQuotes          = lldb.kNumFormats + 4
eFormatUtf8String               = lldb.kNumFormats + 5
eFormatUtf8StringNoQuotes       = lldb.kNumFormats + 6
eFormatWideString               = lldb.kNumFormats + 7
eFormatWideStringNoQuotes       = lldb.kNumFormats + 8
eFormatUtf32String              = lldb.kNumFormats + 9
eFormatUtf32StringNoQuotes      = lldb.kNumFormats + 10

eFormatBasicSpecsMask = (1 << 6) - 1
eFormatFlagSpecsMask = (1 << 20) - 1 - ((1 << 6) - 1)

eFormatNoAddress = 1 << 6
eFormatNoDerived = 1 << 7
eFormatNoRawView = 1 << 8
eFormatRawView   = 1 << 9
eFormatAsArray   = 1 << 10

eFormatInheritedFlagsMask = ~eFormatRawView
# @formatter:on

TYPE_VIZ_FORMAT_SPEC_TO_LLDB_FORMAT_MAP = {
    TypeVizFormatSpec.DECIMAL: lldb.eFormatDecimal,
    TypeVizFormatSpec.OCTAL: lldb.eFormatOctal,
    TypeVizFormatSpec.HEX: lldb.eFormatHex,
    TypeVizFormatSpec.HEX_UPPERCASE: lldb.eFormatHexUppercase,
    TypeVizFormatSpec.HEX_NO_PREFIX: eFormatHexNoPrefix,
    TypeVizFormatSpec.HEX_UPPERCASE_NO_PREFIX: eFormatHexUppercaseNoPrefix,
    TypeVizFormatSpec.BINARY: lldb.eFormatBinary,
    TypeVizFormatSpec.BINARY_NO_PREFIX: eFormatBinaryNoPrefix,
    TypeVizFormatSpec.SCIENTIFIC: lldb.eFormatFloat,  # TODO
    TypeVizFormatSpec.SCIENTIFIC_MIN: lldb.eFormatFloat,  # TODO
    TypeVizFormatSpec.CHARACTER: lldb.eFormatChar,
    TypeVizFormatSpec.STRING: lldb.eFormatCString,
    TypeVizFormatSpec.STRING_NO_QUOTES: eFormatCStringNoQuotes,
    TypeVizFormatSpec.UTF8_STRING: eFormatUtf8String,
    TypeVizFormatSpec.UTF8_STRING_NO_QUOTES: eFormatUtf8StringNoQuotes,
    TypeVizFormatSpec.WIDE_STRING: eFormatWideString,
    TypeVizFormatSpec.WIDE_STRING_NO_QUOTES: eFormatWideStringNoQuotes,
    TypeVizFormatSpec.UTF32_STRING: eFormatUtf32String,
    TypeVizFormatSpec.UTF32_STRING_NO_QUOTES: eFormatUtf32StringNoQuotes,
    TypeVizFormatSpec.ENUM: lldb.eFormatEnum,
    TypeVizFormatSpec.HEAP_ARRAY: lldb.eFormatDefault,  # TODO
    TypeVizFormatSpec.IGNORED: lldb.eFormatDefault,
}

TYPE_VIZ_FORMAT_FLAGS_TO_LLDB_FORMAT_MAP = {
    TypeVizFormatFlags.NO_ADDRESS: eFormatNoAddress,
    TypeVizFormatFlags.NO_DERIVED: eFormatNoDerived,
    TypeVizFormatFlags.NO_RAW_VIEW: eFormatNoRawView,
    TypeVizFormatFlags.NUMERIC_RAW_VIEW: lldb.eFormatDefault,  # TODO
    TypeVizFormatFlags.RAW_FORMAT: eFormatRawView,
}

FMT_STRING_SET = {lldb.eFormatCString: (1, "", '__locale__'),
                  eFormatUtf8String: (1, "", 'utf-8'),
                  eFormatWideString: (2, "L", 'utf-16'),
                  eFormatUtf32String: (4, "U", 'utf-32')}
FMT_STRING_NOQUOTES_SET = {eFormatCStringNoQuotes: (1, "", '__locale__'),
                           eFormatUtf8StringNoQuotes: (1, "", 'utf-8'),
                           eFormatWideStringNoQuotes: (2, "L", 'utf-16'),
                           eFormatUtf32StringNoQuotes: (4, "U", 'utf-32')}
FMT_STRING_SET_ALL = {**FMT_STRING_SET, **FMT_STRING_NOQUOTES_SET}

FMT_UNQUOTE_MAP = {
    lldb.eFormatCString: eFormatCStringNoQuotes,
    eFormatUtf8String: eFormatUtf8StringNoQuotes,
    eFormatWideString: eFormatWideStringNoQuotes,
    eFormatUtf32String: eFormatUtf32StringNoQuotes,
}


def get_custom_view_id(format_spec: int) -> int:
    return format_spec >> 20


def set_custom_view_id(format_spec: int, custom_view_spec=0) -> int:
    return format_spec | (custom_view_spec << 20)
