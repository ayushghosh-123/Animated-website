from __future__ import annotations

from enum import Enum, auto
from typing import Optional

from jb_declarative_formatters.type_name_template import TypeNameTemplate
from six import StringIO


class TypeNameParsingError(Exception):

    def __init__(self, stream: str, pos: int, message: str) -> None:
        super(TypeNameParsingError, self).__init__('"{}":{}: {}'.format(stream, pos, message))
        self.stream: str = stream
        self.pos: int = pos


class DefaultDiagHandler(object):
    def raise_error(self, error: TypeNameParsingError):
        raise error


def parse_type_name_template(type_name: str, diag_handler: Optional[DefaultDiagHandler] = None) -> TypeNameTemplate:
    diag_handler = diag_handler or DefaultDiagHandler()
    lexer = Lexer(type_name, diag_handler)
    parser = Parser(lexer, diag_handler)
    return parser.parse_type_name()


class TokenType(Enum):
    UNKNOWN = auto()
    END = auto(),
    IDENT = auto(),
    LESS = auto(),
    GREATER = auto(),
    COMMA = auto(),
    MUL = auto(),
    LPARENT = auto(),
    RPARENT = auto(),
    AMPERSAND = auto(),


class Token(object):

    def __init__(self, tt: TokenType, text: str, pos: int):
        self.tt: TokenType = tt
        self.text: str = text
        self.pos: int = pos

    def __str__(self) -> str:
        if self.text:
            return self.text
        return self.tt.name


class Lexer(object):
    WHITESPACES = [' ', '\n', '\t']
    TT_MAP = {
        '<': TokenType.LESS,
        '>': TokenType.GREATER,
        ',': TokenType.COMMA,
        '*': TokenType.MUL,
        '(': TokenType.LPARENT,
        ')': TokenType.RPARENT,
        '&': TokenType.AMPERSAND,
    }

    def __init__(self, characters: str, diag_handler: DefaultDiagHandler):
        self.stream: str = characters
        self.stream_len: int = len(self.stream)
        self.diag_handler: DefaultDiagHandler = diag_handler
        self.pos: int = 0

    def fetch(self) -> Token:
        # skip whitespaces
        while self.pos < self.stream_len and self.stream[self.pos] in self.WHITESPACES:
            self.pos += 1

        if self.pos >= self.stream_len:
            return Token(TokenType.END, '', self.pos)

        tok_start_pos = self.pos
        c = self.stream[self.pos]
        self.pos += 1

        possible_tt = self.TT_MAP.get(c, None)
        if possible_tt is not None:
            return Token(possible_tt, c, tok_start_pos)

        # interprete anything else as identifier
        while self.pos < self.stream_len:
            c = self.stream[self.pos]
            if c in self.WHITESPACES:
                break
            if c in self.TT_MAP:
                break
            self.pos += 1

        ident = self.stream[tok_start_pos:self.pos]
        return Token(TokenType.IDENT, ident, tok_start_pos)

    def _raise_error(self, message: str):
        self.diag_handler.raise_error(self._make_error(message))

    def _make_error(self, message: str):
        return TypeNameParsingError(self.stream, self.pos, message)


class Parser(object):

    def __init__(self, lexer: Lexer, diag_handler: DefaultDiagHandler):
        self.lexer: Lexer = lexer
        self.diag_handler: DefaultDiagHandler = diag_handler
        self.token: Token | None = None
        self.advance()

    def advance(self) -> None:
        self.token = self.lexer.fetch()

    def tt(self) -> TokenType:
        return self.token.tt

    def parse_type_name(self) -> TypeNameTemplate:
        ident = self._parse_type_name_template()
        if self.tt() != TokenType.END:
            self._raise_unexpected_token_error('<END>')
        return ident

    def _parse_type_name_template(self) -> TypeNameTemplate:
        ident = StringIO()
        fmt = StringIO()
        args = []

        iteration_count = 0
        original_text_name: Optional[str] = None

        while True:
            match self.tt():
                case TokenType.IDENT:
                    name, original_text_name = self._parse_name()
                    ident.write(name)
                    fmt.write(name)

                    if self.tt() == TokenType.LESS:
                        original_text_name = None
                        ident.write(self.token.text)
                        fmt.write(self.token.text)
                        self.advance()

                        if self.tt() != TokenType.GREATER:
                            args_part, args_fmt = self._parse_type_list()
                            # write format string to substitute template arguments
                            fmt.write(args_fmt)
                            args.extend(args_part)

                        if self.tt() != TokenType.GREATER:
                            self._raise_unexpected_token_error('\'>\'')

                        ident.write(self.token.text)
                        fmt.write(self.token.text)

                        self.advance()

                case TokenType.LESS:
                    # try to parse as  lambda anonymous class name <lambda_...>
                    ident.write(self.token.text)
                    fmt.write(self.token.text)

                    self.advance()

                    if self.tt() != TokenType.IDENT:
                        self._raise_unexpected_token_error('<lambda>')

                    if not self.token.text.startswith('lambda_'):
                        self._raise_unexpected_token_error('<lambda>')

                    ident.write(self.token.text)
                    fmt.write(self.token.text)

                    self.advance()

                    if self.tt() != TokenType.GREATER:
                        self._raise_unexpected_token_error('\'>\'')

                    ident.write(self.token.text)
                    fmt.write(self.token.text)

                    self.advance()

                case TokenType.MUL:
                    ident.write(self.token.text)
                    fmt.write(self.token.text)

                    self.advance()

                case TokenType.AMPERSAND:
                    ident.write(self.token.text)
                    fmt.write(self.token.text)

                    self.advance()

                case TokenType.LPARENT:
                    ident.write(self.token.text)
                    fmt.write(self.token.text)

                    self.advance()

                    if self.tt() != TokenType.RPARENT:
                        self._parse_signature(ident, fmt, args)

                    if self.tt() != TokenType.RPARENT:
                        self._raise_unexpected_token_error('\')\'')

                    ident.write(self.token.text)
                    fmt.write(self.token.text)

                    self.advance()
                case _:
                    break
            iteration_count += 1

        def get_original_text_name_for_simple_types() -> Optional[str]:
            return original_text_name if iteration_count == 1 else None

        return TypeNameTemplate(ident.getvalue(),
                                fmt.getvalue(),
                                args,
                                get_original_text_name_for_simple_types())

    def _parse_name(self) -> tuple[str, str]:
        start_orig_text = self.token.pos
        end_orig_text = self.lexer.pos
        ident = self.token.text
        self.advance()
        was_ident = True
        while True:
            space = ''
            match self.tt():
                case TokenType.IDENT:
                    if was_ident:
                        space = ' '
                    was_ident = True
                    end_orig_text = self.lexer.pos
                case TokenType.MUL | TokenType.AMPERSAND:
                    was_ident = False
                    end_orig_text = self.lexer.pos
                case _:
                    return ident, self.lexer.stream[start_orig_text:end_orig_text]
            ident += space + self.token.text
            self.advance()

    def _parse_type_list(self) -> (list[TypeNameTemplate], str):
        args = []
        fmt = StringIO()

        # parse type|*[,...]
        cur_type = self._parse_type_name_or_wildcard()
        args.append(cur_type)
        fmt.write('{}')

        while self.tt() == TokenType.COMMA:
            fmt.write(self.token.text)
            self.advance()

            cur_type = self._parse_type_name_or_wildcard()
            args.append(cur_type)
            fmt.write('{}')

        return args, fmt.getvalue()

    def _parse_signature(self, ident: StringIO, fmt: StringIO, args):
        # parse type[,...]
        cur_type = self._parse_type_name_template()
        ident.write(cur_type.name)
        fmt.write(cur_type.fmt)
        args.extend(cur_type.args)

        while self.tt() == TokenType.COMMA:
            fmt.write(self.token.text)
            ident.write(self.token.text)
            self.advance()

            cur_type = self._parse_type_name_template()
            ident.write(cur_type.name)
            fmt.write(cur_type.fmt)
            args.extend(cur_type.args)

    def _parse_type_name_or_wildcard(self) -> TypeNameTemplate:
        if self.tt() == TokenType.MUL:
            ident = self.token.text
            self.advance()
            return TypeNameTemplate(ident)

        return self._parse_type_name_template()

    def _raise_unexpected_token_error(self, expected_message) -> None:
        self._raise_error('Unexpected token \'{}\', expected {}'.format(self.token, expected_message))

    def _raise_error(self, message) -> None:
        self.diag_handler.raise_error(self._make_error(message))

    def _make_error(self, message) -> TypeNameParsingError:
        return TypeNameParsingError(self.lexer.stream, self.token.pos, message)
