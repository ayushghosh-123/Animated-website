from __future__ import annotations

import re
import traceback
from collections.abc import Iterable
from typing import Optional
from xml.etree import ElementTree
from xml.etree.ElementTree import Element
from xml.sax import saxutils

from jb_declarative_formatters import *
from jb_declarative_formatters.parsers.type_name_parser import parse_type_name_template, TypeNameParsingError
from jb_declarative_formatters.type_viz import TypeVizIntrinsic, TypeVizIntrinsicParameter, \
    IntrinsicsScope, IntrinsicCall, create_intrinsic
from jb_declarative_formatters.type_viz_expression import TypeVizCondition
from jb_declarative_formatters.type_viz_item_nodes import *
from jb_declarative_formatters.type_viz_item_providers import TypeVizItemProviderCustomListItems
from jb_declarative_formatters.type_viz_storage import DirectAcyclicGraph
from lldb.formatters.Logger import Logger
from renderers.jb_lldb_logging import get_suppress_errors
from six import StringIO

# noinspection HttpUrlsUsage
NATVIS_SCHEMA_NAMESPACE = 'http://schemas.microsoft.com/vstudio/debugger/natvis/2010'


class NatvisIntrinsicXmlDefinition(object):
    def __init__(self, name: str, expression: str, optional: bool,
                 parameters: list[TypeVizIntrinsicParameter],
                 dependencies: list[IntrinsicCall]):
        self.parameters = parameters
        self.name: str = name
        self.optional = optional
        self.expression: str = expression
        self.dependencies = dependencies


class NatvisParsingError(Exception):
    pass


_NS = {'natvis': NATVIS_SCHEMA_NAMESPACE}


# noinspection PyBroadException
def natvis_parse_file(path: str, logger: Logger = None) -> Iterable[TypeViz]:
    def log(msg: str):
        if not logger:
            return
        logger >> msg

    try:
        tree = ElementTree.parse(path)
        root = tree.getroot()
    except ElementTree.ParseError:
        # xml parsing error
        error_message = f"XmlError on parsing file {path}. {traceback.format_exc()}"
        log(error_message)
        if not get_suppress_errors():
            raise NatvisParsingError(error_message)
        return []

    try:
        intrinsics = _parse_global_intrinsics_nodes(logger, root)
    except Exception:
        error_message = f"Error on parsing global Intrinsics in file {path}. {traceback.format_exc()}"
        log(error_message)
        if not get_suppress_errors():
            raise NatvisParsingError(error_message)
        return []

    for node_type_name in root.findall('natvis:Type', _NS):
        # noinspection PyBroadException
        try:
            yield natvis_parse_type(node_type_name, intrinsics, logger)
        except NatvisParsingError:
            # expected parsing error happened
            # - skip node and continue
            log(f"NatvisParsingError on parsing node {node_type_name} in file {path}. Traceback: {traceback.format_exc()}")
            continue
        except Exception:
            # unexpected parsing error happened
            log(f"Error on parsing node {node_type_name} in file {path}. Traceback: {traceback.format_exc()}")
            continue


def _unescape(value):
    if value is None:
        return value
    return saxutils.unescape(value)


def _make_tag(tag):
    return '{{{}}}{}'.format(NATVIS_SCHEMA_NAMESPACE, tag)


def _parse_type_name_alternatives(node_type_name):
    try:
        name = node_type_name.attrib['Name']
    except KeyError:
        raise NatvisParsingError("Missing required attribute 'Name'")

    name = _unescape(name)

    # support non-documented way to declare alternative type names used from UE4.17
    for alt_name in name.split('|'):
        yield alt_name

    # support non-documented AlternativeType nodes found in stl.natvis
    for alt_name_node in node_type_name.findall('natvis:AlternativeType', _NS):
        yield _unescape(alt_name_node.attrib['Name'])


__local_priorities_parser_values = {
    'Low': 1,
    'MediumLow': 2,
    'Medium': 3,
    'MediumHigh': 4,
    'High': 5,
}


def _parse_type_priority(node_type_name) -> int:
    priority_str = node_type_name.attrib.get('Priority', 'Medium')
    try:
        return __local_priorities_parser_values[priority_str]
    except KeyError:
        raise NatvisParsingError('Unknown priority {}'.format(priority_str))


__local_boolean_parser_values = {
    'true': True,
    '1': True,
    'false': False,
    '0': False,
}


def _parse_boolean(node, attrib_name, default) -> bool:
    value = node.attrib.get(attrib_name, default)
    try:
        return __local_boolean_parser_values[value]
    except KeyError:
        raise NatvisParsingError('Can\'t parse boolean value {}'.format(value))


def natvis_parse_type(node_type_name: Element, global_scope_intrinsics: IntrinsicsScope,
                      logger: Logger) -> TypeViz:
    _item_node_parsers = {
        _make_tag('Item'): _natvis_node_parse_item,
        _make_tag('ExpandedItem'): _natvis_node_parse_expanded_item,
        _make_tag('ArrayItems'): _natvis_node_parse_array_items,
        _make_tag('IndexListItems'): _natvis_node_parse_index_list_items,
        _make_tag('LinkedListItems'): _natvis_node_parse_linked_list_items,
        _make_tag('TreeItems'): _natvis_node_parse_tree_items,
        _make_tag('CustomListItems'): _natvis_node_parse_custom_list_items,
    }

    type_viz_names = list[TypeVizName]()
    alt_names = _parse_type_name_alternatives(node_type_name)
    for alt_name in alt_names:
        try:
            if logger:
                logger >> "Parsing type name '{}'".format(alt_name)

            name_ast = parse_type_name_template(alt_name)
        except TypeNameParsingError as e:
            raise NatvisParsingError(e)
        type_viz_names.append(TypeVizName(alt_name, name_ast))

    inheritable = _parse_boolean(node_type_name, 'Inheritable', 'true')
    include_view = _natvis_node_parse_include_view(node_type_name)
    exclude_view = _natvis_node_parse_exclude_view(node_type_name)
    priority = _parse_type_priority(node_type_name)

    type_scope_intrinsics = _parse_type_intrinsics_nodes(logger, node_type_name, global_scope_intrinsics)

    type_viz_obj = TypeViz(type_viz_names, inheritable, include_view,
                           exclude_view, priority,
                           global_scope_intrinsics.retain_only_lazy(),
                           type_scope_intrinsics.retain_only_lazy(), logger)

    all_intrinsics_list = [type_scope_intrinsics, global_scope_intrinsics]

    for display_string_node in node_type_name.findall('natvis:DisplayString', _NS):
        value = _natvis_node_parse_expression(display_string_node.text or '', all_intrinsics_list, logger)
        condition = _natvis_node_parse_condition(display_string_node, all_intrinsics_list, logger)
        optional = _natvis_node_parse_optional(display_string_node)
        display_string_expression = _natvis_node_parse_interpolated_string(value, all_intrinsics_list, logger)
        type_viz_obj.summaries.append(TypeVizSummary(display_string_expression, condition, optional))

    expand_node = node_type_name.find('natvis:Expand', _NS)
    if expand_node is not None:
        type_viz_obj.item_providers = []

        type_viz_obj.hide_raw_view = _parse_boolean(expand_node, 'HideRawView', 'false')

        for node in expand_node:
            parse_fn = _item_node_parsers.get(node.tag)
            if parse_fn:
                item_provider = parse_fn(node, all_intrinsics_list, logger)
                if item_provider:
                    type_viz_obj.item_providers.append(item_provider)
    return type_viz_obj


class ArgsCountParser:
    def __init__(self, expression: str, pos: int):
        self._expr = expression
        self._pos = pos
        self._expr_len = len(expression)

    def _current(self) -> str:
        assert self._pos < self._expr_len
        return self._expr[self._pos]

    def _next(self) -> None:

        self._pos += 1

    def _peek(self, next_offset: int = 1) -> str | None:
        pos_next = self._pos + next_offset
        if pos_next < self._expr_len:
            return self._expr[pos_next]
        return None

    def get_args_count(self) -> tuple[int, int]:
        return self._get_args_count_impl(')')

    def _get_args_count_impl(self, exit_sym: str = None) -> tuple[int, int]:
        count = 0
        was_arg = False
        while self._pos < self._expr_len:
            current = self._current()
            if current == '"':
                was_arg = True
                self.skip_string()
                continue

            elif current == '/' and self._peek() == '*':
                self.skip_comment()
                continue

            elif current == "'":
                self.skip_ansii_char()
                continue

            elif current == '(':
                was_arg = True
                self._next()
                self._get_args_count_impl(')')
                continue

            elif current == ')' and exit_sym == current:
                count = count + (1 if was_arg else 0)
                self._next()
                break
            elif current.isspace():
                self._next()
                continue
            elif current == ',':
                count += 1
                was_arg = False
                self._next()
                continue

            elif current == '{':
                was_arg = True
                self._next()
                self._get_args_count_impl('}')
                continue
            elif current == '[':
                was_arg = True
                self._next()
                self._get_args_count_impl(']')
                continue
            elif current in ']}' and exit_sym == current:
                self._next()
                break
            else:
                was_arg = True
                self._next()

        return count, self._pos

    def skip_string(self) -> None:
        assert self._current() == '"'
        self._next()

        while self._pos < self._expr_len and self._current() != '"':
            if self._current() == '\\':
                # skipping this and next symbol
                self._next()

            self._next()

        # last '"'
        self._next()

    def skip_comment(self):
        self._next()
        self._next()

        while self._current() != '*' or self._peek() != '/':
            self._next()

        self._next()
        self._next()

    # noinspection SpellCheckingInspection
    def skip_ansii_char(self):
        self._next()


def _count_args(expr: str, pos: int) -> tuple[int, int]:
    d = ArgsCountParser(expr, pos)
    return d.get_args_count()


g_intrinsics_in_expression = dict[str, list[IntrinsicCall]]()
g_call_expression_regex = re.compile("(?<!\\.)(?<!->)\\b(?P<func_name>[a-zA-Z_]\\w*)\\s*\\(")


def _get_all_intrinsic_calls_from_expression(expression: str) -> list[IntrinsicCall]:
    cached = g_intrinsics_in_expression.get(expression, None)
    if cached:
        return cached

    depends = list[IntrinsicCall]()
    for m in g_call_expression_regex.finditer(expression):
        intrinsic_name = m.group('func_name')
        args_count, args_end_pos = _count_args(expression, m.end())
        depends.append(IntrinsicCall(intrinsic_name, args_count, m.end(), args_end_pos))

    g_intrinsics_in_expression[expression] = depends

    return depends


def _sort_intrinsics_by_their_dependencies(intrinsics: list[TypeVizIntrinsic]) -> list[TypeVizIntrinsic]:
    # we can't use graphlib.TopologicalSorter because we have next case:
    # A = B()
    # A = 10
    # B = A()
    # and this case works in VS

    if not len(intrinsics):
        return []

    def get_children(intrinsic: TypeVizIntrinsic) -> list[TypeVizIntrinsic]:
        res = []
        for dep in intrinsic.unique_dependencies:
            for tmp in intrinsics:
                if dep == tmp.name:
                    res.append(tmp)
        return res

    graph = DirectAcyclicGraph(intrinsics, get_children)
    sorted_list = graph.sort()

    return sorted_list


def _parse_global_intrinsics_nodes(logger: Logger, root: Element) -> IntrinsicsScope:
    intrinsics = _parse_intrinsics_nodes(logger, root, None, 'global')
    return intrinsics


def _parse_type_intrinsics_nodes(logger: Logger, node_type_name: Element,
                                 global_intrinsics: IntrinsicsScope) -> IntrinsicsScope:
    intrinsics = _parse_intrinsics_nodes(logger, node_type_name, global_intrinsics, 'type')
    return intrinsics


def _parse_intrinsics_nodes(logger: Logger, node_type_name: Element,
                            global_intrinsics: IntrinsicsScope | None,
                            intrinsic_scope_name: str) -> IntrinsicsScope:
    intrinsics_from_xml = list[NatvisIntrinsicXmlDefinition]()

    intrinsic_overloads = dict[str, int]()

    for intrinsic_node in node_type_name.findall('natvis:Intrinsic', _NS):
        intrinsic = _natvis_node_parse_intrinsic(intrinsic_node, logger)
        current_count = intrinsic_overloads.get(intrinsic.name, 0)
        intrinsic_overloads[intrinsic.name] = current_count + 1
        intrinsics_from_xml.append(intrinsic)

    intrinsics_list = list[TypeVizIntrinsic]()

    for intrinsic in intrinsics_from_xml:
        intrinsics_list.append(
            create_intrinsic(
                intrinsic_overloads, intrinsic.name, intrinsic.expression,
                intrinsic.optional, intrinsic.parameters,
                intrinsic.dependencies))

    sorted_list = _sort_intrinsics_by_their_dependencies(intrinsics_list)

    intrinsics = IntrinsicsScope(sorted_list, intrinsic_scope_name)

    all_intrinsics_list = [intrinsics]
    if global_intrinsics is not None:
        all_intrinsics_list.append(global_intrinsics)

    for intrinsic in intrinsics.sorted_list:
        changed_expression = _apply_intrinsics_to_expression(
            intrinsic.expression,
            all_intrinsics_list, logger)

        intrinsic.change_expression(changed_expression)
    return intrinsics


# noinspection SpellCheckingInspection
NATVIS_FORMAT_SPECIFIERS_MAPPING = {
    'd': TypeVizFormatSpec.DECIMAL,
    'o': TypeVizFormatSpec.OCTAL,
    'x': TypeVizFormatSpec.HEX,
    'h': TypeVizFormatSpec.HEX,
    'X': TypeVizFormatSpec.HEX_UPPERCASE,
    'H': TypeVizFormatSpec.HEX_UPPERCASE,
    'xb': TypeVizFormatSpec.HEX_NO_PREFIX,
    'hb': TypeVizFormatSpec.HEX_NO_PREFIX,
    'Xb': TypeVizFormatSpec.HEX_UPPERCASE_NO_PREFIX,
    'Hb': TypeVizFormatSpec.HEX_UPPERCASE_NO_PREFIX,
    'b': TypeVizFormatSpec.BINARY,
    'bb': TypeVizFormatSpec.BINARY_NO_PREFIX,
    'e': TypeVizFormatSpec.SCIENTIFIC,
    'g': TypeVizFormatSpec.SCIENTIFIC_MIN,
    'c': TypeVizFormatSpec.CHARACTER,
    's': TypeVizFormatSpec.STRING,
    'sb': TypeVizFormatSpec.STRING_NO_QUOTES,
    's8': TypeVizFormatSpec.UTF8_STRING,
    's8b': TypeVizFormatSpec.UTF8_STRING_NO_QUOTES,
    'su': TypeVizFormatSpec.WIDE_STRING,
    'sub': TypeVizFormatSpec.WIDE_STRING_NO_QUOTES,
    'bstr': TypeVizFormatSpec.WIDE_STRING,
    's32': TypeVizFormatSpec.UTF32_STRING,
    's32b': TypeVizFormatSpec.UTF32_STRING_NO_QUOTES,
    'en': TypeVizFormatSpec.ENUM,
    'hv': TypeVizFormatSpec.HEAP_ARRAY,
    'hr': TypeVizFormatSpec.IGNORED,
    'wc': TypeVizFormatSpec.IGNORED,
    'wm': TypeVizFormatSpec.IGNORED,
}

NATVIS_FORMAT_FLAGS_MAPPING = {
    'na': TypeVizFormatFlags.NO_ADDRESS,
    'nd': TypeVizFormatFlags.NO_DERIVED,
    'nr': TypeVizFormatFlags.NO_RAW_VIEW,
    'nvo': TypeVizFormatFlags.NUMERIC_RAW_VIEW,
    '!': TypeVizFormatFlags.RAW_FORMAT,
}
NATVIS_FORMAT_FLAGS = NATVIS_FORMAT_FLAGS_MAPPING.keys()

_NATVIS_LITERAL_ARRAY_REGEX = re.compile(r"^\d+$")
_NATVIS_SPECS_REGEX = re.compile(r"^(?:\[(.*)])?(.*)$")
_NATVIS_VIEW_SPECS_REGEX = re.compile(r"^(?:view\s*\((.*)\))?(.*)$")


def _natvis_parse_expression_specs(specs):
    simple_match = _NATVIS_LITERAL_ARRAY_REGEX.match(specs)
    if simple_match:
        array_len = simple_match.group(0)
        if array_len:
            array_len = array_len.strip()
            return array_len, None, None, None

    match = _NATVIS_SPECS_REGEX.match(specs)
    if not match:
        return None, None, None, None

    array_len = match.group(1)
    if array_len:
        array_len = array_len.strip()
    spec = match.group(2)
    if spec:
        spec = spec.strip()

    view_spec = None
    view_match = _NATVIS_VIEW_SPECS_REGEX.match(spec)
    if view_match:
        view_spec = view_match.group(1)
        if view_spec:
            view_spec = view_spec.strip()

    spec = view_match.group(2)
    spec_value, spec_flags = _natvis_parse_format_specs(spec)

    return array_len, spec_value, spec_flags, view_spec


def _natvis_parse_format_specs(spec: str):
    spec_flags: TypeVizFormatFlags | None = TypeVizFormatFlags(0)
    idx = 0
    while True:
        for flag_name, flag in NATVIS_FORMAT_FLAGS_MAPPING.items():
            if spec.startswith(flag_name, idx):
                spec_flags |= flag
                idx += len(flag_name)
                break
        else:
            break
    spec = spec[idx:]
    if spec_flags == 0:
        spec_flags = None

    return NATVIS_FORMAT_SPECIFIERS_MAPPING.get(spec, None), spec_flags


def _apply_intrinsics_to_expression(expression: str,
                                    intrinsics_scopes: list[IntrinsicsScope],
                                    logger: Logger) -> str:
    found_intrinsics = _get_all_intrinsic_calls_from_expression(expression)

    new_str_parts = list[str]()
    current_pos = 0
    last_call_pos = -1

    for intrinsic_call in found_intrinsics:
        assert intrinsic_call.args_begin_pos > last_call_pos
        last_call_pos = intrinsic_call.args_begin_pos

        intrinsic: TypeVizIntrinsic | None = None
        current_scope: IntrinsicsScope | None = None

        for intrinsics_scope in intrinsics_scopes:

            intrinsic_index = intrinsics_scope.name_to_indexes_map.get(intrinsic_call.name, None)
            if intrinsic_index is None:
                continue

            intrinsic = intrinsics_scope.sorted_list[intrinsic_index[0]]
            current_scope = intrinsics_scope
            break

        if not intrinsic:
            continue

        replace_text, replace_start_pos, replace_end_pos = intrinsic.get_intrinsic_call_replacement(
            expression, intrinsic_call, current_scope.intrinsic_scope_name)

        new_str_parts.append(expression[current_pos:replace_start_pos])
        new_str_parts.append(replace_text)
        current_pos = replace_end_pos

        for intrinsic_index in current_scope.name_to_indexes_map[intrinsic_call.name]:
            current_scope.sorted_list[intrinsic_index].mark_as_used()

    new_str_parts.append(expression[current_pos:])
    new_str = ''.join(new_str_parts)

    if logger and current_pos != 0:
        logger >> f"replaced intrinsic '{expression}' >> '{new_str}'"

    return new_str


def _natvis_node_parse_expression(expression_text: str,
                                  intrinsics_scopes: list[IntrinsicsScope] | None,
                                  logger: Logger) -> Optional[str]:
    if expression_text is None:
        return None
    expression_text = _unescape(expression_text)
    expression_text = expression_text.replace('\n', '')

    if not intrinsics_scopes:
        return expression_text

    return _apply_intrinsics_to_expression(expression_text, intrinsics_scopes, logger)


def _natvis_node_parse_formatted_expression(expression_text: str,
                                            intrinsics_scopes: list[IntrinsicsScope],
                                            logger: Logger) -> Optional[TypeVizExpression]:
    if expression_text is None:
        return None
    expression_text = _unescape(expression_text)
    expression_text = expression_text.replace('\n', '')

    parts = expression_text.rsplit(',', 1)
    array_size = None
    format_spec = None
    format_flags = None
    view_spec = None
    if len(parts) == 2:
        specs = parts[1].strip()
        array_size, format_spec, format_flags, view_spec = _natvis_parse_expression_specs(specs)

    if array_size or format_spec or format_flags or view_spec:
        expression = parts[0].strip()
    else:
        expression = expression_text.strip()

    expression = _apply_intrinsics_to_expression(expression, intrinsics_scopes, logger)
    return TypeVizExpression(expression, array_size, format_spec, format_flags, view_spec)


def _natvis_node_parse_interpolated_string(text: str, intrinsics_scopes: list[IntrinsicsScope], logger: Logger):
    text_len = len(text)
    i = 0
    parts_list = []
    cur_part = StringIO()
    while i < text_len:
        if text[i] == '{':
            i += 1
            if i < text_len and text[i] == '{':
                # '{{' is escaped '{'
                cur_part.write('{')
                i += 1
                continue

            idx_start = i
            # get expression slice to evaluate
            while i < text_len:
                if text[i] == '}':
                    break
                i += 1
            else:
                raise NatvisParsingError("missing '}'")

            expr = _natvis_node_parse_formatted_expression(text[idx_start:i], intrinsics_scopes, logger)
            parts_list.append((cur_part.getvalue(), expr))
            i += 1  # skip closing }
            cur_part = StringIO()  # start new non-evaluated part
            continue

        if text[i] == '}':
            cur_part.write('}')
            i += 1
            if i < text_len and text[i] == '}':
                # '}}' is escaped '}'
                i += 1
            continue

        cur_part.write(text[i])
        i += 1

    last_part = cur_part.getvalue()
    if last_part:
        parts_list.append((last_part, None))
    return TypeVizInterpolatedString(parts_list)


def _natvis_node_parse_optional_name(item_node: Element) -> str | None:
    return _natvis_node_parse_optional_attribute(item_node, 'Name')


def _natvis_node_parse_required_name(item_node: Element) -> str:
    return _natvis_node_parse_required_attribute(item_node, 'Name')


def _natvis_node_parse_required_type(item_node: Element) -> str:
    return _natvis_node_parse_required_attribute(item_node, 'Type')


def _natvis_node_parse_optional_attribute(node: Element, attr_name: str) -> str | None:
    return _unescape(node.get(attr_name, None))


def _natvis_node_parse_required_attribute(node: Element, attr_name: str) -> str:
    value = node.get(attr_name, None)
    if value is None:
        raise NatvisParsingError(f"Missing required attribute '{attr_name}'")

    return _unescape(value)


def _natvis_node_parse_item(item_node: Element, intrinsics_scopes: list[IntrinsicsScope],
                            logger: Logger):
    item_name = _natvis_node_parse_required_name(item_node)
    item_condition = _natvis_node_parse_condition(item_node, intrinsics_scopes, logger)
    item_optional = _natvis_node_parse_optional(item_node)
    item_expression = _natvis_node_parse_formatted_expression(item_node.text or '', intrinsics_scopes, logger)
    return TypeVizItemProviderSingle(item_name, item_expression, item_condition, item_optional)


def _natvis_node_parse_expanded_item(item_node: Element, intrinsics_scopes: list[IntrinsicsScope],
                                     logger: Logger):
    item_condition = _natvis_node_parse_condition(item_node, intrinsics_scopes, logger)
    item_optional = _natvis_node_parse_optional(item_node)
    item_expression = _natvis_node_parse_formatted_expression(item_node.text or '', intrinsics_scopes, logger)
    return TypeVizItemProviderExpanded(item_expression, item_condition,
                                       item_optional)


def _natvis_node_parse_size_node(item_node: Element, intrinsics_scopes: list[IntrinsicsScope], logger: Logger):
    nodes = item_node.findall('natvis:Size', _NS)
    if nodes is None:
        return None

    values = []
    for node in nodes:
        condition = _natvis_node_parse_condition(node, intrinsics_scopes, logger)
        optional = _natvis_node_parse_optional(node)
        value = _natvis_node_parse_expression(node.text or '', intrinsics_scopes, logger)

        values.append(TypeVizItemSizeTypeNode(value, condition, optional))

    return values


def _natvis_node_parse_value_pointer_node(item_node: Element, intrinsics_scopes: list[IntrinsicsScope], logger: Logger):
    nodes = item_node.findall('natvis:ValuePointer', _NS)
    if nodes is None:
        return None

    values = []
    for node in nodes:
        condition = _natvis_node_parse_condition(node, intrinsics_scopes, logger)
        value = _natvis_node_parse_formatted_expression(node.text or '', intrinsics_scopes, logger)

        values.append(TypeVizItemValuePointerTypeNode(value, condition))

    return values


def _natvis_node_parse_array_items(item_node: Element,
                                   intrinsics_scopes: list[IntrinsicsScope],
                                   logger: Logger):
    item_condition = _natvis_node_parse_condition(item_node, intrinsics_scopes, logger)
    item_optional = _natvis_node_parse_optional(item_node)

    items_size = _natvis_node_parse_size_node(item_node, intrinsics_scopes, logger)
    if items_size is None:
        return None

    items_value_pointer = _natvis_node_parse_value_pointer_node(item_node, intrinsics_scopes, logger)
    if items_value_pointer is None:
        return None

    return TypeVizItemProviderArrayItems(items_size,
                                         items_value_pointer,
                                         item_condition, item_optional)


def _natvis_node_parse_index_node(item_node: Element, intrinsics_scopes: list[IntrinsicsScope], logger: Logger):
    nodes = item_node.findall('natvis:ValueNode', _NS)
    if nodes is None:
        return None

    values = []
    for node in nodes:
        condition = _natvis_node_parse_condition(node, intrinsics_scopes, logger)
        value = _natvis_node_parse_formatted_expression(node.text or '', intrinsics_scopes, logger)

        values.append(TypeVizItemIndexNodeTypeNode(value, condition))

    return values


def _natvis_node_parse_index_list_items(item_node: Element,
                                        intrinsics_scopes: list[IntrinsicsScope],
                                        logger: Logger):
    item_condition = _natvis_node_parse_condition(item_node, intrinsics_scopes, logger)
    item_optional = _natvis_node_parse_optional(item_node)

    items_size = _natvis_node_parse_size_node(item_node, intrinsics_scopes, logger)
    if items_size is None:
        return None

    items_value_node = _natvis_node_parse_index_node(item_node, intrinsics_scopes, logger)
    if items_value_node is None:
        return None

    return TypeVizItemProviderIndexListItems(items_size, items_value_node,
                                             item_condition, item_optional)


def _natvis_node_parse_linked_list_head_pointer(item_node: Element, intrinsics_scopes: list[IntrinsicsScope],
                                                logger: Logger):
    nodes = item_node.findall('natvis:HeadPointer', _NS)
    if nodes is None:
        return None

    if len(nodes) != 1:
        raise NatvisParsingError('Only one HeadPointer node allowed')
    node = nodes[0]

    node_expression = _natvis_node_parse_expression(node.text or '', intrinsics_scopes, logger)

    return TypeVizItemListItemsHeadPointerTypeNode(node_expression)


def _natvis_node_parse_linked_list_next_pointer(item_node: Element, intrinsics_scopes: list[IntrinsicsScope],
                                                logger: Logger):
    nodes = item_node.findall('natvis:NextPointer', _NS)
    if nodes is None:
        return None

    if len(nodes) != 1:
        raise NatvisParsingError('Only one NextPointer node allowed')
    node = nodes[0]

    node_expression = _natvis_node_parse_expression(node.text or '', intrinsics_scopes, logger)

    return TypeVizItemListItemsNextPointerTypeNode(node_expression)


ElementToTypeViz = tuple[Element, Optional[TypeVizExpression], Optional[TypeVizInterpolatedString]]


def _internal_parse_value_node(item_node: Element,
                               intrinsics_scopes: list[IntrinsicsScope],
                               logger: Logger
                               ) -> ElementToTypeViz | None:
    nodes = item_node.findall('natvis:ValueNode', _NS)
    if nodes is None:
        return None

    if len(nodes) != 1:
        raise NatvisParsingError('Only one ValueNode node allowed')
    node = nodes[0]

    node_name_str = _natvis_node_parse_optional_name(node)
    node_name = _natvis_node_parse_interpolated_string(
        node_name_str, intrinsics_scopes, logger) if node_name_str is not None else None
    node_expression = _natvis_node_parse_formatted_expression(node.text or '', intrinsics_scopes, logger)

    return node, node_expression, node_name


def _natvis_node_parse_linked_list_value_node(item_node: Element, intrinsics_scopes: list[IntrinsicsScope],
                                              logger: Logger):
    node, node_expression, node_name = _internal_parse_value_node(item_node, intrinsics_scopes, logger)
    return TypeVizItemListItemsIndexNodeTypeNode(node_expression, node_name)


def _natvis_node_parse_linked_list_items(item_node: Element,
                                         intrinsics_scopes: list[IntrinsicsScope],
                                         logger: Logger):
    item_condition = _natvis_node_parse_condition(item_node, intrinsics_scopes, logger)
    item_optional = _natvis_node_parse_optional(item_node)

    items_size = _natvis_node_parse_size_node(item_node, intrinsics_scopes, logger)
    # size can be omitted

    item_head_pointer = _natvis_node_parse_linked_list_head_pointer(item_node, intrinsics_scopes, logger)
    if item_head_pointer is None:
        return None

    item_next_pointer = _natvis_node_parse_linked_list_next_pointer(item_node, intrinsics_scopes, logger)
    if item_next_pointer is None:
        return None

    items_value_node = _natvis_node_parse_linked_list_value_node(item_node, intrinsics_scopes, logger)
    if items_value_node is None:
        return None

    return TypeVizItemProviderLinkedListItems(items_size, item_head_pointer, item_next_pointer, items_value_node,
                                              item_condition, item_optional)


def _natvis_node_parse_tree_pointer_helper(item_node: Element,
                                           node_name: str,
                                           intrinsics_scopes: list[IntrinsicsScope],
                                           logger: Logger):
    nodes = item_node.findall('natvis:{}'.format(node_name), _NS)
    if nodes is None:
        return None

    if len(nodes) != 1:
        raise NatvisParsingError('Only one {} node allowed'.format(node_name))
    node = nodes[0]

    node_expression = _natvis_node_parse_expression(node.text or '', intrinsics_scopes, logger)
    return node_expression


def _natvis_node_parse_tree_head_pointer(item_node: Element, intrinsics_scopes: list[IntrinsicsScope], logger: Logger):
    node_expression = _natvis_node_parse_tree_pointer_helper(item_node, 'HeadPointer', intrinsics_scopes, logger)
    if node_expression is None:
        return None
    return TypeVizItemTreeHeadPointerTypeNode(node_expression)


def _natvis_node_parse_tree_child_pointer(item_node: Element,
                                          node_name: str,
                                          intrinsics_scopes: list[IntrinsicsScope],
                                          logger: Logger):
    node_expression = _natvis_node_parse_tree_pointer_helper(item_node, node_name, intrinsics_scopes, logger)
    if node_expression is None:
        return None
    return TypeVizItemTreeChildPointerTypeNode(node_expression)


def _natvis_node_parse_tree_value_node(item_node: Element, intrinsics_scopes: list[IntrinsicsScope], logger: Logger):
    node, node_expression, node_name = _internal_parse_value_node(item_node, intrinsics_scopes, logger)
    node_condition = _natvis_node_parse_condition(node, intrinsics_scopes, logger)

    return TypeVizItemTreeNodeTypeNode(node_expression, node_name, node_condition)


def _natvis_node_parse_tree_items(item_node: Element,
                                  intrinsics_scopes: list[IntrinsicsScope],
                                  logger: Logger):
    item_condition = _natvis_node_parse_condition(item_node, intrinsics_scopes, logger)
    item_optional = _natvis_node_parse_optional(item_node)

    items_size = _natvis_node_parse_size_node(item_node, intrinsics_scopes, logger)
    # size can be omitted

    item_head_pointer = _natvis_node_parse_tree_head_pointer(item_node, intrinsics_scopes, logger)
    if item_head_pointer is None:
        return None

    item_left_pointer = _natvis_node_parse_tree_child_pointer(item_node, 'LeftPointer', intrinsics_scopes, logger)
    if item_left_pointer is None:
        return None

    item_right_pointer = _natvis_node_parse_tree_child_pointer(item_node, 'RightPointer', intrinsics_scopes, logger)
    if item_right_pointer is None:
        return None

    items_value_node = _natvis_node_parse_tree_value_node(item_node, intrinsics_scopes, logger)
    if items_value_node is None:
        return None

    return TypeVizItemProviderTreeItems(items_size, item_head_pointer,
                                        item_left_pointer, item_right_pointer,
                                        items_value_node,
                                        item_condition, item_optional)


def _natvis_node_parse_variable_nodes(item_node: Element, intrinsics_scopes: list[IntrinsicsScope], logger: Logger):
    nodes = item_node.findall('natvis:Variable', _NS)
    if nodes is None:
        return None

    variables = []
    for node in nodes:
        name = _natvis_node_parse_required_name(node)

        initial_value_text = node.attrib.get('InitialValue', '')
        initial_value = _natvis_node_parse_expression(initial_value_text, intrinsics_scopes, logger)
        variables.append(TypeVizItemVariableTypeNode(name, initial_value))

    return variables


def _natvis_node_parse_code_block_nodes(item_node: Element, intrinsics_scopes: list[IntrinsicsScope], logger: Logger):
    def _parse_condition(code_block_node):
        return _natvis_node_parse_expression(code_block_node.attrib.get('Condition'), intrinsics_scopes, logger)

    def _parse_exec(code_block_node):
        condition = _parse_condition(code_block_node)
        expression = _natvis_node_parse_expression(code_block_node.text or '', intrinsics_scopes, logger)
        return TypeVizItemExecCodeBlockTypeNode(condition, expression)

    def _parse_loop(code_block_node):
        condition = _parse_condition(code_block_node)
        code_blocks = _natvis_node_parse_code_block_nodes(code_block_node, intrinsics_scopes, logger)
        return TypeVizItemLoopCodeBlockTypeNode(condition, code_blocks)

    def _parse_if(code_block_node):
        condition = _parse_condition(code_block_node)
        code_blocks = _natvis_node_parse_code_block_nodes(code_block_node, intrinsics_scopes, logger)
        return TypeVizItemIfCodeBlockTypeNode(condition, code_blocks)

    def _parse_else_if(code_block_node):
        condition = _parse_condition(code_block_node)
        code_blocks = _natvis_node_parse_code_block_nodes(code_block_node, intrinsics_scopes, logger)
        return TypeVizItemElseIfCodeBlockTypeNode(condition, code_blocks)

    def _parse_else(code_block_node):
        code_blocks = _natvis_node_parse_code_block_nodes(code_block_node, intrinsics_scopes, logger)
        return TypeVizItemElseCodeBlockTypeNode(code_blocks)

    def _parse_break(code_block_node):
        condition = _parse_condition(code_block_node)
        return TypeVizItemBreakCodeBlockTypeNode(condition)

    def _parse_item(code_block_node):
        condition = _parse_condition(code_block_node)
        expression = _natvis_node_parse_formatted_expression(code_block_node.text or '', intrinsics_scopes, logger)
        raw_name = _natvis_node_parse_optional_name(code_block_node)
        name = _natvis_node_parse_interpolated_string(raw_name, intrinsics_scopes, logger) if raw_name else None
        return TypeVizItemItemCodeBlockTypeNode(condition, name, expression)

    _code_block_node_parsers = {
        _make_tag('Exec'): _parse_exec,
        _make_tag('Loop'): _parse_loop,
        _make_tag('If'): _parse_if,
        _make_tag('Elseif'): _parse_else_if,
        _make_tag('Else'): _parse_else,
        _make_tag('Break'): _parse_break,
        _make_tag('Item'): _parse_item,
    }

    result = []

    for node in item_node:
        parse_fn = _code_block_node_parsers.get(node.tag)
        if parse_fn:
            code_block = parse_fn(node)
            if code_block:
                result.append(code_block)

    return result


def _natvis_node_parse_custom_list_items(item_node: Element,
                                         intrinsics_scopes: list[IntrinsicsScope],
                                         logger: Logger):
    item_condition = _natvis_node_parse_condition(item_node, intrinsics_scopes, logger)
    item_optional = _natvis_node_parse_optional(item_node)

    variables = _natvis_node_parse_variable_nodes(item_node, intrinsics_scopes, logger)
    # variables can be omitted

    items_size = _natvis_node_parse_size_node(item_node, intrinsics_scopes, logger)
    if items_size is None:
        return None

    code_blocks = _natvis_node_parse_code_block_nodes(item_node, intrinsics_scopes, logger)
    if code_blocks is None:
        return None

    return TypeVizItemProviderCustomListItems(variables,
                                              items_size, code_blocks,
                                              item_condition, item_optional)


def _natvis_node_parse_condition(node: Element, intrinsics_scopes: list[IntrinsicsScope], logger: Logger):
    condition = _natvis_node_parse_expression(node.attrib.get('Condition'), intrinsics_scopes, logger)
    include_view = _natvis_node_parse_include_view(node)
    exclude_view = _natvis_node_parse_exclude_view(node)
    return TypeVizCondition(condition, include_view, exclude_view)


def _natvis_node_parse_optional(node: Element) -> bool:
    return _parse_boolean(node, 'Optional', 'false')


def _natvis_node_parse_exclude_view(node: Element) -> str:
    return node.attrib.get('ExcludeView', '')


def _natvis_node_parse_include_view(node: Element) -> str:
    return node.attrib.get('IncludeView', '')


def _natvis_node_parse_intrinsic_parameter(node: ElementTree.Element) -> TypeVizIntrinsicParameter:
    param_name = _natvis_node_parse_optional_name(node)
    param_type = _natvis_node_parse_required_type(node)

    return TypeVizIntrinsicParameter(param_name, param_type)


def _natvis_node_parse_intrinsic(node: ElementTree.Element, logger: Logger) -> NatvisIntrinsicXmlDefinition:
    name = _natvis_node_parse_optional_name(node)
    expr = _natvis_node_parse_expression(node.attrib['Expression'], None, logger)
    optional = _natvis_node_parse_optional(node)
    dependencies = _get_all_intrinsic_calls_from_expression(expr)

    params = list[TypeVizIntrinsicParameter]()
    for paramNode in node.findall('natvis:Parameter', _NS):
        parsed_param = _natvis_node_parse_intrinsic_parameter(paramNode)
        params.append(parsed_param)

    return NatvisIntrinsicXmlDefinition(name, expr, optional, params, dependencies)
