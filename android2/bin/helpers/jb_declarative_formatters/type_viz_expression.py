from enum import IntEnum, IntFlag, auto
from six import StringIO


class TypeVizFormatSpec(IntEnum):
    DECIMAL = auto()
    OCTAL = auto()
    HEX = auto()
    HEX_UPPERCASE = auto()
    HEX_NO_PREFIX = auto()
    HEX_UPPERCASE_NO_PREFIX = auto()
    BINARY = auto()
    BINARY_NO_PREFIX = auto()
    SCIENTIFIC = auto()
    SCIENTIFIC_MIN = auto()
    CHARACTER = auto()
    STRING = auto()
    STRING_NO_QUOTES = auto()
    UTF8_STRING = auto()
    UTF8_STRING_NO_QUOTES = auto()
    WIDE_STRING = auto()
    WIDE_STRING_NO_QUOTES = auto()
    UTF32_STRING = auto()
    UTF32_STRING_NO_QUOTES = auto()
    ENUM = auto()
    HEAP_ARRAY = auto()
    IGNORED = auto()


class TypeVizFormatFlags(IntFlag):
    NO_ADDRESS = auto()
    NO_DERIVED = auto()
    NO_RAW_VIEW = auto()
    NUMERIC_RAW_VIEW = auto()
    RAW_FORMAT = auto()


g_view_spec_ids = {}


def get_custom_view_spec_id_by_name(view_spec: str) -> int:
    if view_spec:
        return g_view_spec_ids.setdefault(view_spec, len(g_view_spec_ids) + 1)
    return 0


class TypeVizFormatOptions(object):
    def __init__(self, array_size: str = None, format_spec: TypeVizFormatSpec = None,
                 format_flags: TypeVizFormatFlags = None, view_spec=None):
        self.array_size = array_size
        self.format_spec: TypeVizFormatSpec = format_spec
        self.format_flags: TypeVizFormatFlags = format_flags
        self.view_spec = view_spec
        self.view_spec_id = get_custom_view_spec_id_by_name(view_spec)

    def __str__(self):
        r = ''
        if self.array_size:
            r += " as array[{}]".format(self.array_size)
        if self.format_spec:
            r += " as {}".format(self.format_spec.name)
        if self.view_spec:
            r += " using view {}".format(self.view_spec)
        if self.format_flags:
            r += " with {}".format(str(self.format_flags))
        return r

    def __repr__(self):
        r = ''
        if self.array_size:
            r += "[{}]".format(self.array_size)
        if self.format_spec:
            r += "{}".format(self.format_spec.name)
        if self.view_spec:
            r += " {}".format(self.view_spec)
        if self.format_flags:
            r += " {}".format(str(self.format_flags))
        return r

    def __eq__(self, other):
        if not isinstance(other, TypeVizFormatOptions):
            return False
        if self.array_size != other.array_size:
            return False
        if self.format_spec != other.format_spec:
            return False
        if self.format_flags != other.format_flags:
            return False
        if self.view_spec != other.view_spec:
            return False
        return True


class TypeVizCondition(object):
    def __init__(self, condition: str, include_view: str, exclude_view: str):
        self.condition = condition
        self.include_view = include_view
        self.include_view_id = get_custom_view_spec_id_by_name(include_view)
        self.exclude_view = exclude_view
        self.exclude_view_id = get_custom_view_spec_id_by_name(exclude_view)


class TypeVizExpression(object):
    def __init__(self, text: str, array_size: str = None, format_spec: TypeVizFormatSpec = None,
                 format_flags: TypeVizFormatFlags = None, view_spec=None):
        self.text = text
        self.view_options = TypeVizFormatOptions(array_size, format_spec, format_flags, view_spec)

    def __str__(self):
        r = "'{}'{}".format(self.text, self.view_options)
        return r

    def __repr__(self):
        return repr(self.__dict__)

    def __eq__(self, other):
        if not isinstance(other, TypeVizExpression):
            return False
        if self.text != other.text:
            return False
        if self.view_options != other.view_options:
            return False
        return True

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash((self.text, self.view_options))


class TypeVizInterpolatedString(object):
    def __init__(self, parts_list):
        self.parts_list = parts_list

    def __str__(self):
        result = StringIO()
        for (s, e) in self.parts_list:
            result.write(s)
            if e is not None:
                result.write(str(e))
        return result.getvalue()

    def __repr__(self):
        return repr(self.__dict__)

    def __eq__(self, other):
        if not isinstance(other, TypeVizInterpolatedString):
            return False
        return self.parts_list == other.parts_list

    def __ne__(self, other):
        return not self == other

    def __hash__(self):
        return hash(self.parts_list)
