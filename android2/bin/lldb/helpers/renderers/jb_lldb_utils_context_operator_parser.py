from typing import Callable


class TextRange:
    def __init__(self, start: int, end: int):
        assert start <= end
        self.start = start
        self.end = end


class ModuleReferenceEntry:
    def __init__(self, module_name_range: TextRange, qualified_name_range: TextRange, total_range: TextRange):
        self.module_name_range = module_name_range
        self.qualified_name_range = qualified_name_range
        self.total_range = total_range


class LexerContext:
    def __init__(self, text: str):
        self.text = text
        self.current_pos = 0
        self.end_pos = len(text)
        self.module_reference_entries: list[ModuleReferenceEntry] = []

    def eof(self):
        assert self.current_pos <= self.end_pos
        return self.current_pos == self.end_pos

    def current(self):
        assert self.current_pos <= self.end_pos
        if self.current_pos < self.end_pos:
            return self.text[self.current_pos]
        return None

    def advance(self):
        assert self.current_pos < self.end_pos
        self.current_pos += 1

    def add_module_reference_entry(self, entry: ModuleReferenceEntry):
        self.module_reference_entries.append(entry)


def _is_exclamation_format_module_name_head_char(c):
    return c.isalpha() or \
        c == '_' or \
        c == '@' or \
        c == '$'


def _is_exclamation_format_module_name_tail_char(c):
    return _is_exclamation_format_module_name_head_char(c) or \
        c.isdigit() or \
        c == '-'


def _is_curly_brackets_format_module_name_head_char(c):
    return c.isalnum() or \
        c in ["_", "-", ",", ";", "!", ".", "(", ")", "[", "]", "{", "@", "&", "%", "^", "+", "=", "~", "$"]


def _is_curly_brackets_format_module_name_tail_char(c):
    return _is_curly_brackets_format_module_name_head_char(c) or \
        c == ' '


def _is_identifier_head(c):
    return 'A' <= c <= 'Z' or \
        'a' <= c <= 'z' or \
        c == '_'


g_unary_operators = ['*', '+', '-', '&', '!']


def _is_unary_operator(c):
    return c in g_unary_operators


def _is_identifier_trail(c):
    return 'A' <= c <= 'Z' or \
        'a' <= c <= 'z' or \
        '0' <= c <= '9' or \
        c == '_'


def _parse_ws(ctx: LexerContext):
    assert ctx.current() == ' '
    while ctx.current() == ' ':
        ctx.advance()


def _parse_string_literal(ctx: LexerContext):
    assert ctx.current() == '"'
    ctx.advance()

    while True:
        if ctx.eof():
            return
        match ctx.current():
            case '"':
                ctx.advance()
                break
            case '\\':
                ctx.advance()
                if ctx.eof():
                    return
                if ctx.current() == '"':
                    ctx.advance()
            case _:
                ctx.advance()


def _parse_identifier(ctx: LexerContext):
    assert _is_identifier_head(ctx.current())
    ctx.advance()

    while not ctx.eof() and _is_identifier_trail(ctx.current()):
        ctx.advance()


def _parse_exclamation_format_module_name(ctx: LexerContext):
    assert _is_exclamation_format_module_name_head_char(ctx.current())
    start = ctx.current_pos
    while not ctx.eof() and _is_exclamation_format_module_name_tail_char(ctx.current()):
        ctx.advance()

    if not ctx.eof() and ctx.current() == '.':
        ctx.advance()
        current = ctx.current()
        while current is not None and current.isalnum():
            ctx.advance()
            current = ctx.current()

    end = ctx.current_pos
    return TextRange(start, end)


def _parse_curly_brackets_format_module_name(ctx: LexerContext):
    assert _is_curly_brackets_format_module_name_head_char(ctx.current())
    start = ctx.current_pos
    while not ctx.eof() and _is_curly_brackets_format_module_name_tail_char(ctx.current()):
        ctx.advance()

    # '.' (dot) already included in allowed charset. We don't need to parse it here

    end = ctx.current_pos
    return TextRange(start, end)


def _parse_qualified_name(ctx: LexerContext) -> TextRange:
    assert _is_identifier_head(ctx.current())
    start = ctx.current_pos
    _parse_identifier(ctx)

    _skip_space(ctx)

    while True:
        old_pos = ctx.current_pos
        if ctx.current() != ':':
            break
        ctx.advance()

        if ctx.current() != ':':
            break
        ctx.advance()

        _skip_space(ctx)

        if not _is_identifier_head(ctx.current()):
            break

        _parse_identifier(ctx)

    ctx.current_pos = old_pos
    end = ctx.current_pos
    return TextRange(start, end)


def _parse_potential_exclamation_module_name(ctx: LexerContext) -> None:
    assert _is_exclamation_format_module_name_head_char(ctx.current())

    module_name_range = _parse_exclamation_format_module_name(ctx)

    _skip_space(ctx)

    if ctx.current() != '!':
        return

    ctx.advance()

    _skip_space(ctx)

    if not _is_identifier_head(ctx.current()):
        return

    qualified_name_range = _parse_qualified_name(ctx)
    ctx.add_module_reference_entry(ModuleReferenceEntry(
        module_name_range,
        qualified_name_range,
        TextRange(module_name_range.start, qualified_name_range.end)))


def _skip_space(ctx: LexerContext):
    while not ctx.eof() and ctx.current() == ' ':
        ctx.advance()


def _parse_curly_brackets(ctx: LexerContext):
    assert (ctx.current() == '{')
    total_start = ctx.current_pos
    ctx.advance()

    _skip_space(ctx)

    if ctx.current() != ',':
        return
    ctx.advance()

    _skip_space(ctx)

    if ctx.current() != ',':
        return
    ctx.advance()

    _skip_space(ctx)

    if not _is_curly_brackets_format_module_name_head_char(ctx.current()):
        return

    module_name_range = _parse_curly_brackets_format_module_name(ctx)

    _skip_space(ctx)

    if ctx.current() != '}':
        return

    ctx.advance()

    start_expression = end_expression = ctx.current_pos

    ctx.add_module_reference_entry(ModuleReferenceEntry(
        module_name_range,
        TextRange(start_expression, end_expression),
        TextRange(total_start, end_expression)))


def _parse(ctx: LexerContext):
    while True:
        if ctx.eof():
            break
        c = ctx.current()

        if c == ' ':
            _parse_ws(ctx)
        elif c == '"':
            _parse_string_literal(ctx)
        elif _is_exclamation_format_module_name_head_char(c):
            _parse_potential_exclamation_module_name(ctx)
        elif c == '{':
            _parse_curly_brackets(ctx)
        else:
            ctx.advance()


def replace_context_operators_in_text(text: str, repl: Callable[[str, str], str]) -> str:
    ctx = LexerContext(text)
    _parse(ctx)

    output_string = ""
    last_pos = 0
    for e in ctx.module_reference_entries:
        assert e.total_range.start >= last_pos
        output_string += text[last_pos: e.total_range.start]
        module_name = text[e.module_name_range.start: e.module_name_range.end].strip()
        qualified_name = text[e.qualified_name_range.start: e.qualified_name_range.end].strip()
        output_string += repl(module_name, qualified_name)
        last_pos = e.total_range.end

    output_string += text[last_pos:]
    return output_string
