from __future__ import annotations

import re
from typing import List, Tuple, Union, Sequence

from jb_declarative_formatters import *
from jb_declarative_formatters.type_name_template import TypeNameTemplate
from jb_declarative_formatters.type_viz_expression import TypeVizFormatOptions, TypeVizCondition
from jb_declarative_formatters.type_viz_item_nodes import TypeVizItemExecCodeBlockTypeNode, \
    TypeVizItemItemCodeBlockTypeNode, TypeVizItemIfCodeBlockTypeNode, TypeVizItemElseCodeBlockTypeNode, \
    TypeVizItemElseIfCodeBlockTypeNode, TypeVizItemLoopCodeBlockTypeNode, TypeVizItemBreakCodeBlockTypeNode, \
    TypeVizItemVariableTypeNode
from renderers.jb_lldb_builtin_formatters import StructChildrenProvider
from renderers.jb_lldb_declarative_formatters_options import *
from renderers.jb_lldb_format import overlay_child_format, update_value_dynamic_state, overlay_summary_format
from renderers.jb_lldb_format_specs import *
from renderers.jb_lldb_logging import get_suppress_errors
from renderers.jb_lldb_utils import *

g_cache_variables_initialized: dict[str, bool] = dict()


class NatVisDescriptor(AbstractVisDescriptor):
    def __init__(self, candidates: List[Tuple[TypeViz, TypeVizName]], name_template: TypeNameTemplate):
        self.type_name_template = name_template
        self.viz_candidates = [(viz, viz_name, _match_type_viz_template(viz_name.type_name_template, name_template)) for
                               viz, viz_name in candidates]

    def output_summary(self, value_non_synth: lldb.SBValue, stream: Stream):

        for name_viz_pair in self.viz_candidates:
            viz, type_viz_name, matches = name_viz_pair
            old_context = set_global_intrinsics_context(IntrinsicsContext(
                global_intrinsic_scope=viz.global_intrinsics, type_intrinsic_scope=viz.type_intrinsics))
            try:
                log("Trying visualizer for type '{}'...", str(type_viz_name))
                if not _check_include_exclude_view_condition(viz, value_non_synth):
                    continue

                if not viz.summaries:
                    log('No user provided summary found, return default...')
                    return self.output_summary_from_children(value_non_synth, stream)

                # try to choose candidate from ordered display string expressions
                success = _find_first_good_node(_process_summary_node, viz.summaries, value_non_synth,
                                                matches, stream)
                if success is not None:
                    return

            except EvaluateError:
                continue
            finally:
                set_global_intrinsics_context(old_context)

        log("No matching display string candidate found, fallback to default")
        return self.output_summary_from_children(value_non_synth, stream)

    def output_summary_from_children(self, value_non_synth, stream):
        children_provider = self.prepare_children(value_non_synth)
        num_children = children_provider.num_children()

        stream.output("{")
        if stream.length > get_max_string_length():
            stream.output('...')
        elif num_children == 0:
            stream.output('...')
        else:
            for child_index in range(num_children):
                child: lldb.SBValue = children_provider.get_child_at_index(child_index)
                child_non_synth = child.GetNonSyntheticValue()
                child_name = child_non_synth.GetName() or ''
                if child_name == RAW_VIEW_ITEM_NAME:
                    continue
                if child_index != 0:
                    stream.output(", ")

                if child_index > 2 or stream.length > get_max_string_length():
                    stream.output("...")
                    break

                stream.output(child_name)
                stream.output("=")
                if stream.length > get_max_string_length():
                    stream.output("...")
                    break

                stream.output_object(child_non_synth)

        stream.output("}")

    def prepare_children(self, value_non_synth: lldb.SBValue):
        value_name = value_non_synth.GetName()
        value_type_name = value_non_synth.GetType().GetName()
        log("Initial retrieving children of value named '{}' of type '{}'...", value_name, value_type_name)

        viz = None
        providers = None
        start_indexes = None
        level = get_recursion_level()
        if level >= g_max_recursion_level - 1:
            log("Natvis visualizer for type '{}' of value '{}' has been ignored: "
                "recursion level exceeds the maximum supported limit of {}",
                value_type_name, value_name, g_max_recursion_level)
        else:
            for name_viz_pair in self.viz_candidates:
                viz, type_viz_name, matches = name_viz_pair
                try:
                    if not _check_include_exclude_view_condition(viz, value_non_synth):
                        continue
                    else:
                        old_context = set_global_intrinsics_context(
                            IntrinsicsContext(
                                global_intrinsic_scope=viz.global_intrinsics, type_intrinsic_scope=viz.type_intrinsics))
                        try:
                            set_recursion_level(level + 1)
                            providers, start_indexes = _try_update_child_providers(
                                value_non_synth, viz, type_viz_name,
                                self.type_name_template)
                        finally:
                            set_recursion_level(level)
                            set_global_intrinsics_context(old_context)

                except EvaluateError as error:
                    log("Error occurred: {}", error)
                    continue
                break

        if providers is None:
            log("No child provider found for '{}'", value_non_synth.GetType().GetName())
            return StructChildrenProvider(value_non_synth)

        return NatVisChildrenProvider(value_non_synth, viz, providers, start_indexes)


class NatVisChildrenProvider(AbstractChildrenProvider):
    def __init__(self, value_non_synth: lldb.SBValue, viz, providers, child_providers_start_indexes):
        self.viz: TypeViz = viz
        self.child_providers: list[AbstractChildrenProvider] = providers
        self.child_providers_start_indexes = child_providers_start_indexes
        self.format_spec = value_non_synth.GetFormat()

    def num_children(self):
        if self.child_providers:
            return sum(child_prov.num_children() for child_prov in self.child_providers)
        else:
            return 0

    def has_children(self):
        has_children = self.viz and bool(self.viz.item_providers)
        return has_children

    def get_child_index(self, name):
        if not self.child_providers:
            return INVALID_CHILD_INDEX

        for prov in self.child_providers:
            # noinspection PyBroadException
            try:
                index = prov.get_child_index(name)
            except Exception:
                # some unexpected error happened
                if not get_suppress_errors():
                    raise
                return INVALID_CHILD_INDEX

            if index != INVALID_CHILD_INDEX:
                return index

        return INVALID_CHILD_INDEX

    def get_child_at_index(self, index):
        if not self.child_providers:
            return None

        child_provider, relative_index = self._find_child_provider(index)
        if not child_provider:
            return None

        # noinspection PyBroadException
        try:
            child: lldb.SBValue = child_provider.get_child_at_index(relative_index)
            if child is not None:
                # apply inheritable formatting from parent value
                overlay_child_format(child, self.format_spec)
            return child
        except Exception:
            # some unexpected error happened
            if not get_suppress_errors():
                raise
            return None

    def _find_child_provider(self, index):
        # TODO: binary search, not linear
        for i, start_idx in enumerate(self.child_providers_start_indexes):
            if start_idx > index:
                # return previous provider
                prov_index = i - 1
                break
        else:
            # last provider
            prov_index = len(self.child_providers) - 1

        if prov_index == -1:
            return None, index

        prov = self.child_providers[prov_index]
        child_start_idx = self.child_providers_start_indexes[prov_index]

        return prov, (index - child_start_idx)


def _match_type_viz_template(type_viz_type_name_template: TypeNameTemplate,
                             type_name_template: TypeNameTemplate) -> Tuple[str, ...]:
    wildcard_matches: list[TypeNameTemplate] = []
    if not type_viz_type_name_template.match(type_name_template, wildcard_matches):
        raise Exception("Inconsistent type matching: can't match template {} with {}"
                        .format(type_name_template, type_viz_type_name_template))

    wildcard_matches_as_str = _fix_wildcard_matches(wildcard_matches)
    return tuple(wildcard_matches_as_str)


def optional_node_processor(fn):
    def wrapped(node, *args, **kwargs):
        assert isinstance(node, TypeVizItemOptionalNodeMixin)
        try:
            return fn(node, *args, **kwargs)
        except EvaluateError:
            if not node.optional:
                raise
        except Exception:
            raise
        return None

    return wrapped


def _evaluate_interpolated_string_to_stream(stream: Stream,
                                            interp_string: TypeVizInterpolatedString,
                                            ctx_val: lldb.SBValue,
                                            wildcards=None,
                                            context=None):
    max_stream_length = get_max_string_length()

    nested_stream = stream.create_nested()
    for (s, expr) in interp_string.parts_list:
        if nested_stream.length > max_stream_length:
            break
        nested_stream.output(s)
        if expr is not None:
            if nested_stream.length > max_stream_length:
                break
            _eval_display_string_expression(nested_stream, ctx_val, expr, wildcards, context)

    stream.output(str(nested_stream))
    return True


def _evaluate_interpolated_string(interp_string: TypeVizInterpolatedString, ctx_val, wildcards=None, context=None):
    target = ctx_val.GetTarget()
    is64bit: bool = target.GetAddressByteSize() == 8
    stream = Stream(is64bit, get_recursion_level())
    _evaluate_interpolated_string_to_stream(stream, interp_string, ctx_val, wildcards, context)
    return str(stream)


def _check_include_exclude_view_condition(viz: TypeViz, value_non_synth: lldb.SBValue) -> bool:
    if viz.include_view_id != 0:
        if get_custom_view_id(value_non_synth.GetFormat()) != viz.include_view_id:
            log("IncludeView condition is not satisfied '{}'...", str(viz.include_view))
            return False
    if viz.exclude_view_id != 0:
        if get_custom_view_id(value_non_synth.GetFormat()) == viz.exclude_view_id:
            log("ExcludeView condition is not satisfied '{}'...", str(viz.exclude_view))
            return False
    return True


@optional_node_processor
def _process_summary_node(summary: TypeVizSummary, ctx_val: lldb.SBValue, wildcards, stream: Stream):
    # ctx_val is NonSynthetic
    if summary.condition:
        if not _process_node_condition(summary.condition, ctx_val, wildcards):
            return None

    if not _evaluate_interpolated_string_to_stream(stream, summary.value, ctx_val, wildcards):
        return None
    return True


def _fix_wildcard_matches(matches: list[TypeNameTemplate]) -> list[str]:
    # remove breaking type prefixes from typenames
    def _remove_type_prefix(typename: str) -> str:
        prefix_list = ['struct ', 'class ']
        for prefix in prefix_list:
            if typename.startswith(prefix):
                typename = typename[len(prefix):]
        return typename

    return [_remove_type_prefix(str(t)) for t in matches]


def _try_update_child_providers(val_obj_non_synth: lldb.SBValue, viz: TypeViz, type_viz_name: TypeVizName,
                                type_name_template: TypeNameTemplate):
    log("Trying visualizer for type '{}'...", str(type_viz_name))
    wildcard_matches = _match_type_viz_template(type_viz_name.type_name_template, type_name_template)
    child_providers = _build_child_providers(viz.item_providers, val_obj_non_synth,
                                             wildcard_matches,
                                             viz.hide_raw_view) if viz.item_providers is not None else None
    child_providers_start_indexes = None

    if child_providers:
        start_idx = 0
        child_providers_start_indexes = []
        for prov in child_providers:
            child_providers_start_indexes.append(start_idx)
            start_idx += prov.num_children()

    return child_providers, child_providers_start_indexes


def _check_condition(val, condition, context=None):
    res = eval_expression(val, '(bool)(' + condition + ')', None, context)
    if not res.GetValueAsUnsigned():
        return False
    return True


TEMPLATE_REGEX = re.compile(r'\$T([1-9][0-9]*)')


def _resolve_wildcards(expr: str, wildcards: Sequence[str]):
    expr_len = len(expr)
    i = 0
    s = StringIO()
    while i < expr_len:
        m = TEMPLATE_REGEX.search(expr, i)
        if m is None:
            s.write(expr[i:])
            break

        s.write(m.string[i:m.start()])
        wildcard_idx = int(m.group(1)) - 1
        try:
            replacement = wildcards[wildcard_idx]
        except IndexError:
            replacement = m.string[m.start():m.end()]
        s.write(replacement)
        i = m.end()
        if i < expr_len and replacement and replacement[-1] == '>' and expr[i] == '>':
            # write extra space between >>
            s.write(' ')

    return s.getvalue()


def _resolve_wildcards_in_interpolated_string(interp_string: TypeVizInterpolatedString, wildcards):
    parts_list = []
    for part in interp_string.parts_list:
        expr = part[1]
        if expr is None:
            parts_list.append((part[0], None))
            continue

        text = _resolve_wildcards(expr.text, wildcards)
        options = expr.view_options
        array_size = _resolve_wildcards(options.array_size, wildcards) if options.array_size else None
        format_spec = options.format_spec
        view_spec = options.view_spec
        expr = TypeVizExpression(text, array_size, format_spec, view_spec)
        parts_list.append((part[0], expr))

    return TypeVizInterpolatedString(parts_list)


def _convert_format_flags(format_flags: TypeVizFormatFlags) -> int:
    flags = 0
    for from_, to in TYPE_VIZ_FORMAT_FLAGS_TO_LLDB_FORMAT_MAP.items():
        if format_flags & from_:
            flags |= to
    return flags


def _apply_value_formatting(val: lldb.SBValue, format_spec: TypeVizFormatSpec, format_flags: TypeVizFormatFlags,
                            size: Optional[int], format_view_spec: int):
    fmt = lldb.eFormatDefault
    # both format_spec and format_view_spec can't be set simultaneously
    if format_spec is not None:
        fmt = TYPE_VIZ_FORMAT_SPEC_TO_LLDB_FORMAT_MAP.get(format_spec, lldb.eFormatDefault)
    elif format_view_spec != 0:
        fmt = format_view_spec << 20

    if format_flags:
        fmt |= _convert_format_flags(format_flags)

    val_root = get_root_value(val)

    if size is not None:
        fmt |= eFormatAsArray
        val_root.SetFormatAsArraySize(size)

    # noinspection PyArgumentList
    val_root.SetFormat(fmt)

    if fmt & eFormatNoDerived:
        val.SetPreferDynamicValue(lldb.eNoDynamicValues)

    return val


def _eval_display_string_expression(stream: Stream, ctx, expr, wildcards, context):
    if stream.level >= g_max_recursion_level:
        return

    expr_text = _resolve_wildcards(expr.text, wildcards) if wildcards else expr.text
    opts = expr.view_options

    result = eval_expression(ctx, expr_text, None, context)
    result_non_synth = result.GetNonSyntheticValue()
    err = result_non_synth.GetError()
    if err.Fail():
        stream.output("???")
        return

    array_size_expr = opts.array_size
    if array_size_expr is not None and wildcards:
        array_size_expr = _resolve_wildcards(array_size_expr, wildcards)
    size = _eval_expression_result_array_size(ctx, array_size_expr) if array_size_expr is not None else None
    result = _apply_value_formatting(result, opts.format_spec, opts.format_flags, size,
                                     opts.view_spec_id)
    # parent value size formatting is not ignored only for summaries
    overlay_summary_format(result, ctx)

    stream.output_object(result_non_synth)


def _process_node_condition(condition: TypeVizCondition,
                            ctx_val: lldb.SBValue, wildcards, index_str: str = None) -> bool:
    if condition.include_view_id != 0:
        if get_custom_view_id(ctx_val.GetFormat()) != condition.include_view_id:
            return False
    if condition.exclude_view_id != 0:
        if get_custom_view_id(ctx_val.GetFormat()) == condition.exclude_view_id:
            return False
    if condition.condition:
        processed_condition = _resolve_wildcards(condition.condition, wildcards)
        if index_str:
            processed_condition = processed_condition.replace('$i', index_str)

        if not _check_condition(ctx_val, processed_condition, None):
            return False
    return True


def _eval_expression_result_array_size(ctx, size_expr):
    size_value = eval_expression(ctx, size_expr, None)
    size = size_value.GetValueAsSigned()
    if not isinstance(size, int):
        raise EvaluateError('Size value must be of integer type')
    return size


@optional_node_processor
def _node_processor_display_value(node: Union[
    TypeVizItemConditionalNodeMixin, TypeVizItemFormattedExpressionNodeMixin, Optional[TypeVizItemNamedNodeMixin]],
                                  ctx_val: lldb.SBValue, wildcards: tuple):
    if node.condition:
        if not _process_node_condition(node.condition, ctx_val, wildcards):
            return None

    expression = _resolve_wildcards(node.expr.text, wildcards)

    name = node.name if isinstance(node, TypeVizItemNamedNodeMixin) else None
    value = eval_expression(ctx_val, expression, name)
    opts: TypeVizFormatOptions = node.expr.view_options
    array_size_expr = opts.array_size
    if array_size_expr is not None and wildcards:
        array_size_expr = _resolve_wildcards(array_size_expr, wildcards)
    size = _eval_expression_result_array_size(ctx_val, array_size_expr) if array_size_expr is not None else None
    value = _apply_value_formatting(value, opts.format_spec, opts.format_flags, size, opts.view_spec_id)
    return value


class SingleItemProvider(AbstractChildrenProvider):
    def __init__(self, value):
        self.value = value

    def num_children(self):
        return 1

    def get_child_index(self, name):
        if self.value.GetName() == name:
            return 0
        return INVALID_CHILD_INDEX

    def get_child_at_index(self, index):
        assert index == 0
        return self.value


RAW_VIEW_ITEM_NAME = "Raw View"


class RawViewItemProvider(AbstractChildrenProvider):
    def __init__(self, value: lldb.SBValue):
        address = value.GetLoadAddress()
        child = value.CreateValueFromAddress(RAW_VIEW_ITEM_NAME, address, value.GetType())
        set_value_format(child, eFormatRawView)
        self.value = child

    def num_children(self):
        return 1

    def get_child_index(self, name):
        if name == RAW_VIEW_ITEM_NAME:
            return 0
        return INVALID_CHILD_INDEX

    def get_child_at_index(self, index):
        assert index == 0
        return self.value


def _process_item_provider_single(item_provider: TypeVizItemProviderSingle, val: lldb.SBValue, wildcards: tuple):
    item_value = _node_processor_display_value(item_provider, val, wildcards)
    if not item_value:
        return None

    return SingleItemProvider(item_value)


class ExpandedItemProvider(AbstractChildrenProvider):
    def __init__(self, value):
        self.value = value

    def num_children(self):
        num = self.value.GetNumChildren()
        if num != 0 and self.get_child_index(RAW_VIEW_ITEM_NAME) != INVALID_CHILD_INDEX:
            return num - 1
        return num

    def get_child_index(self, name):
        return self.value.GetIndexOfChildWithName(name)

    def get_child_at_index(self, index):
        result: lldb.SBValue = self.value.GetChildAtIndex(index)
        update_value_dynamic_state(result)
        return result if result.GetNonSyntheticValue().GetName() != RAW_VIEW_ITEM_NAME else None


def _process_item_provider_expanded(item_provider, val, wildcards):
    item_value: lldb.SBValue = _node_processor_display_value(item_provider, val, wildcards)
    if not item_value:
        return None
    return ExpandedItemProvider(item_value)


def _find_first_good_node(node_proc, nodes, *args, **kwargs) -> Optional[lldb.SBValue]:
    for node in nodes:
        item_value = node_proc(node, *args, **kwargs)
        if item_value is not None:
            return item_value
    return None


@optional_node_processor
def _node_processor_size(size_node, ctx_val, wildcards):
    assert isinstance(size_node, TypeVizItemSizeTypeNode)
    if size_node.condition:
        if not _process_node_condition(size_node.condition, ctx_val, wildcards):
            return None

    expression = size_node.text
    expression = _resolve_wildcards(expression, wildcards)
    value = eval_expression(ctx_val, expression, None)
    result_value = value.GetValueAsSigned()
    if not isinstance(result_value, int):
        raise EvaluateError('Size value must be of integer type')

    return result_value


def _node_processor_array_items_value_pointer(value_pointer_node, ctx_val, wildcards):
    assert isinstance(value_pointer_node, TypeVizItemValuePointerTypeNode)
    if value_pointer_node.condition:
        if not _process_node_condition(value_pointer_node.condition, ctx_val, wildcards):
            return None

    expr = value_pointer_node.expr
    expression = expr.text
    opts: TypeVizFormatOptions = expr.view_options
    expression = _resolve_wildcards(expression, wildcards)
    value = eval_expression(ctx_val, expression, None)
    array_size_expr = opts.array_size
    if array_size_expr is not None and wildcards:
        array_size_expr = _resolve_wildcards(array_size_expr, wildcards)
    size = _eval_expression_result_array_size(ctx_val, array_size_expr) if array_size_expr is not None else None
    value = _apply_value_formatting(value, opts.format_spec, opts.format_flags, size, opts.view_spec_id)
    return value


class ArrayItemsProvider(AbstractChildrenProvider):
    def __init__(self, size, value_pointer, elem_type):
        self.size = size
        self.value_pointer = value_pointer
        self.elem_type = elem_type
        self.elem_byte_size = elem_type.GetByteSize()

    def num_children(self):
        return self.size

    def get_child_index(self, name):
        try:
            return int(name.lstrip('[').rstrip(']'))
        except ValueError:
            return INVALID_CHILD_INDEX

    def get_child_at_index(self, index):
        child_name = "[{}]".format(index)
        offset = index * self.elem_byte_size
        return self.value_pointer.CreateChildAtOffset(child_name, offset, self.elem_type)


@optional_node_processor
def _node_processor_array_items(array_items_node, ctx_val, wildcards):
    assert isinstance(array_items_node, TypeVizItemProviderArrayItems)
    if array_items_node.condition:
        if not _process_node_condition(array_items_node.condition, ctx_val, wildcards):
            return None

    size = _find_first_good_node(_node_processor_size, array_items_node.size_nodes, ctx_val, wildcards)
    # ???
    if size is None:
        raise EvaluateError('No valid Size node found')

    value_pointer_value = _find_first_good_node(_node_processor_array_items_value_pointer,
                                                array_items_node.value_pointer_nodes, ctx_val, wildcards)
    # ???
    if value_pointer_value is None:
        raise EvaluateError('No valid ValuePointerType node found')

    value_pointer_type = value_pointer_value.GetNonSyntheticValue().GetType()
    if value_pointer_type.IsPointerType():
        elem_type = value_pointer_type.GetPointeeType()
    elif value_pointer_type.IsArrayType():
        elem_type = value_pointer_type.GetArrayElementType()
        value_pointer_value = value_pointer_value.GetNonSyntheticValue().AddressOf()
    else:
        raise EvaluateError('Value pointer is not of pointer or array type ({})'.format(str(value_pointer_type)))

    return ArrayItemsProvider(size, value_pointer_value, elem_type)


def _process_item_provider_array_items(item_provider, val, wildcards):
    return _node_processor_array_items(item_provider, val, wildcards)


LIST_ITEM_SUBSCRIPT_INDEX_REGEX = re.compile(r'\s*\[\s*\$i\s*]\s*')

g_cache_subscript_is_missing = dict[str, dict[str, str]]()


def _trying_eval_list_item_indexed_value(expression: str,
                                         ctx_val: lldb.SBValue,
                                         idx_str: str,
                                         name: str) -> (Optional[lldb.SBValue], Optional[str]):
    try:
        expanded_expression = expression.replace('$i', idx_str)
        value: lldb.SBValue = eval_expression(ctx_val, expanded_expression, name)
        return value, None
    except EvaluateError as evaluate_error:
        type_doesnt_have_subscript = evaluate_error.args and \
                                     evaluate_error.args[0] and \
                                     evaluate_error.args[0].endswith('does not provide a subscript operator')
        if not type_doesnt_have_subscript:
            raise

    log("Subscript operator is missing. Wa are trying to get children via natvis. "
        "At the moment, we only support the simple syntax 'member[$i]'")

    res = LIST_ITEM_SUBSCRIPT_INDEX_REGEX.search(expression)
    if res is None:
        log("We can't find expression '[$i]' for evaluate in '{}'", expression)
        raise EvaluateError("We can't find expression '[$i]' for evaluate")

    another_occurrence = LIST_ITEM_SUBSCRIPT_INDEX_REGEX.search(expression, pos=res.end())
    if another_occurrence is not None:
        log("There are more than one expression '[$i]' in '{}'", expression)
        raise EvaluateError("More than one expression '[$i]'")

    child_item_expression = expression[:res.start()]
    return None, child_item_expression


def _trying_get_indexed_item_value(expression: str,
                                   ctx_val: lldb.SBValue,
                                   idx: int, idx_str: str,
                                   name: str) -> lldb.SBValue:
    type_name = ctx_val.type.name
    if (dict_with_expr := g_cache_subscript_is_missing.get(type_name, None)) is None:
        g_cache_subscript_is_missing[type_name] = dict[str, str]()
    child_item_expression = dict_with_expr.get(expression, None) if dict_with_expr else None

    already_calculated = child_item_expression is not None

    if not already_calculated:
        value, child_item_expression = _trying_eval_list_item_indexed_value(expression, ctx_val, idx_str, name)
        if value:
            return value

    value: lldb.SBValue = eval_expression(ctx_val, child_item_expression, name)

    if not already_calculated:
        child_item_type_name = value.type.name
        # noinspection PyUnusedLocal
        force_evaluate_children_count = value.num_children

        if child_item_type_name not in IndexListItemsProvider.types_with_index_list_items:
            log("IndexListItems expression '{}' doesn't have subscript operator "
                "and doesn't have implementation in natvis type '{}'", expression, child_item_type_name)
            raise EvaluateError("IndexListItems item doesn't have subscript operator")

        g_cache_subscript_is_missing[type_name][expression] = child_item_expression

    return value.GetChildAtIndex(idx)


def _node_processor_index_list_items_value_node(idx: int, name: str,
                                                index_list_value_node: TypeVizItemIndexNodeTypeNode,
                                                ctx_val: lldb.SBValue, wildcards):
    idx_str = str(idx)
    if index_list_value_node.condition:
        if not _process_node_condition(index_list_value_node.condition, ctx_val, wildcards, idx_str):
            return None

    expression = index_list_value_node.expr.text
    expression = _resolve_wildcards(expression, wildcards)

    opts: TypeVizFormatOptions = index_list_value_node.expr.view_options

    value = _trying_get_indexed_item_value(expression, ctx_val, idx, idx_str, name)

    array_size_expr = opts.array_size
    if array_size_expr is not None and wildcards:
        array_size_expr = _resolve_wildcards(array_size_expr, wildcards)
    size = _eval_expression_result_array_size(ctx_val, array_size_expr) if array_size_expr is not None else None
    value = _apply_value_formatting(value, opts.format_spec, opts.format_flags, size, opts.view_spec_id)

    return value


class IndexListItemsProvider(AbstractChildrenProvider):
    types_with_index_list_items: set[str] = set[str]()

    def __init__(self, size, index_list_node, ctx_val, wildcards):
        self.size = size
        self.index_list_node = index_list_node
        self.ctx_val = ctx_val
        self.wildcards = wildcards

        self.types_with_index_list_items.add(ctx_val.type.name)

    def num_children(self):
        return self.size

    def get_child_index(self, name):
        try:
            return int(name.lstrip('[').rstrip(']'))
        except ValueError:
            return INVALID_CHILD_INDEX

    def get_child_at_index(self, index):
        name = "[{}]".format(index)
        value = None
        for value_node_node in self.index_list_node.value_node_nodes:
            value = _node_processor_index_list_items_value_node(index, name, value_node_node, self.ctx_val,
                                                                self.wildcards)
            if value:
                break

        # TODO: show some error value on None
        return value


@optional_node_processor
def _node_processor_index_list_items(index_list_node, ctx_val, wildcards):
    assert isinstance(index_list_node, TypeVizItemProviderIndexListItems)
    if index_list_node.condition:
        if not _process_node_condition(index_list_node.condition, ctx_val, wildcards):
            return None

    size = _find_first_good_node(_node_processor_size, index_list_node.size_nodes, ctx_val, wildcards)
    # ????
    if size is None:
        raise EvaluateError('No valid Size node found')

    return IndexListItemsProvider(size, index_list_node, ctx_val, wildcards)


def _process_item_provider_index_list_items(item_provider, val, wildcards):
    return _node_processor_index_list_items(item_provider, val, wildcards)


def _is_valid_node_ptr(node):
    if node is None:
        return False

    if not node.TypeIsPointerType():
        return False

    return True


def _get_ptr_value(node):
    val = node.GetNonSyntheticValue()
    return val.GetValueAsUnsigned() if _is_valid_node_ptr(val) else 0


class NodesProvider(object):
    def __init__(self):
        self.cache = []
        self.has_more = False
        self.names = None
        self.name2index = None


class CustomItemsProvider(AbstractChildrenProvider):
    def __init__(self, nodes_provider, value_expression, value_opts, wildcards):
        assert isinstance(nodes_provider, NodesProvider)

        self.nodes_cache = nodes_provider.cache
        self.has_more = nodes_provider.has_more
        self.custom_names = nodes_provider.names
        self.custom_name_to_index = nodes_provider.name2index
        self.value_expression = value_expression
        self.value_opts = value_opts
        self.wildcards = wildcards

        self.size = len(self.nodes_cache)

    def num_children(self):
        return self.size

    def get_child_index(self, name):
        if self.custom_name_to_index:
            return self.custom_name_to_index.get(name, INVALID_CHILD_INDEX)

        try:
            return int(name.lstrip('[').rstrip(']'))
        except ValueError:
            return INVALID_CHILD_INDEX

    def get_child_at_index(self, index):
        if index < 0 or index >= self.size:
            return None

        node_value: lldb.SBValue = self.nodes_cache[index]
        if node_value is None:
            return None

        if self.custom_names:
            name = self.custom_names[index]
        else:
            name = "[{}]".format(index)
        value = eval_expression(node_value, self.value_expression, name)
        opts: TypeVizFormatOptions = self.value_opts
        array_size_expr = opts.array_size
        if array_size_expr is not None and self.wildcards:
            array_size_expr = _resolve_wildcards(array_size_expr, self.wildcards)
        size = _eval_expression_result_array_size(node_value, array_size_expr) if array_size_expr is not None else None
        value = _apply_value_formatting(value, opts.format_spec, opts.format_flags, size, opts.view_spec_id)
        return value


class LinkedListIterator(object):
    def __init__(self, node_value, next_expression):
        self.node_value = node_value
        self.next_expression = next_expression

    def __bool__(self):
        return _get_ptr_value(self.node_value) != 0

    def __eq__(self, other):
        return _get_ptr_value(self.node_value) == _get_ptr_value(other.node_value)

    def cur_value(self):
        return self.node_value.GetNonSyntheticValue().Dereference()

    def cur_ptr(self):
        return self.node_value.GetNonSyntheticValue().GetValueAsUnsigned()

    def move_to_next(self):
        self.node_value = self._next()

    def _next(self):
        return eval_expression(self.cur_value(), self.next_expression, None)


class LinkedListIndexedNodesProvider(NodesProvider):
    def __init__(self, size, head_pointer, next_expression):
        super(LinkedListIndexedNodesProvider, self).__init__()

        it = LinkedListIterator(head_pointer, next_expression)

        cache = []
        has_more = False

        # iterate all list nodes and cache them
        start = _get_ptr_value(it.node_value)
        max_size = size if size is not None else g_max_num_children
        idx = 0
        while it and idx < max_size:
            cache.append(it.cur_value())
            idx += 1
            it.move_to_next()

            if it and _get_ptr_value(it.node_value) == start:
                # check for cycled
                break

        if size is None:
            if it and idx >= max_size:
                has_more = True
        else:
            if idx < size:
                cache.extend([None] * (size - idx))

        self.cache = cache
        self.has_more = has_more
        self.names = None
        self.name2index = None


class LinkedListCustomNameNodesProvider(NodesProvider):
    def __init__(self, size, head_pointer, next_expression, custom_value_name, wildcards):
        super(LinkedListCustomNameNodesProvider, self).__init__()

        it = LinkedListIterator(head_pointer, next_expression)

        cache = []
        has_more = False
        names = []
        name2index = {}

        # iterate all list nodes and cache them
        max_size = size if size is not None else g_max_num_children
        idx = 0
        start = _get_ptr_value(it.node_value)
        while it and idx < max_size:
            cur_val = it.cur_value()
            name = _evaluate_interpolated_string(custom_value_name, cur_val, wildcards)
            names.append(name)
            name2index[name] = idx

            cache.append(cur_val)
            idx += 1
            it.move_to_next()

            if it and _get_ptr_value(it.node_value) == start:
                # check for cycled
                break

        if size is None:
            if it and idx >= max_size:
                has_more = True
        else:
            if idx < size:
                cache.extend([None] * (size - idx))

        self.cache = cache
        self.has_more = has_more
        self.names = names
        self.name2index = name2index


def _node_processor_linked_list_items_head_pointer(head_pointer_node, ctx_val, wildcards):
    assert isinstance(head_pointer_node, TypeVizItemListItemsHeadPointerTypeNode)
    expression = _resolve_wildcards(head_pointer_node.text, wildcards)
    return eval_expression(ctx_val, expression, None)


@optional_node_processor
def _node_processor_linked_list_items(linked_list_node, ctx_val, wildcards):
    assert isinstance(linked_list_node, TypeVizItemProviderLinkedListItems)
    if linked_list_node.condition:
        if not _process_node_condition(linked_list_node.condition, ctx_val, wildcards):
            return None

    size = _find_first_good_node(_node_processor_size, linked_list_node.size_nodes, ctx_val, wildcards)
    # size can be None

    head_pointer_value = _node_processor_linked_list_items_head_pointer(linked_list_node.head_pointer_node, ctx_val,
                                                                        wildcards)

    next_pointer_node = linked_list_node.next_pointer_node
    assert isinstance(next_pointer_node, TypeVizItemListItemsNextPointerTypeNode)
    next_pointer_expression = _resolve_wildcards(next_pointer_node.text, wildcards)

    value_node = linked_list_node.value_node_node
    assert isinstance(value_node, TypeVizItemListItemsIndexNodeTypeNode)
    value_expression = _resolve_wildcards(value_node.expr.text, wildcards)
    value_opts = value_node.expr.view_options

    if value_node.name is None:
        nodes_provider = LinkedListIndexedNodesProvider(size, head_pointer_value, next_pointer_expression)
    else:
        nodes_provider = LinkedListCustomNameNodesProvider(size, head_pointer_value, next_pointer_expression,
                                                           value_node.name, wildcards)

    return CustomItemsProvider(nodes_provider, value_expression, value_opts, wildcards)


def _process_item_provider_linked_list_items(item_provider, val, wildcards):
    return _node_processor_linked_list_items(item_provider, val, wildcards)


class BinaryTreeIndexedNodesProvider(NodesProvider):
    def __init__(self, size, head_pointer, left_expression, right_expression, node_condition):
        super(BinaryTreeIndexedNodesProvider, self).__init__()

        cache = []
        has_more = False

        # iterate all list nodes and cache them
        max_size = size if size is not None else g_max_num_children
        idx = 0
        cur = head_pointer
        stack = []  # parents

        def check_condition(node):
            if node_condition is None:
                return True
            return _check_condition(node.GetNonSyntheticValue().Dereference(), node_condition)

        while (_get_ptr_value(cur) != 0 and check_condition(cur) or stack) and idx < max_size:
            while _get_ptr_value(cur) != 0 and check_condition(cur):
                if len(stack) > 100:  # ~2^100 nodes can't be true - something went wrong
                    raise Exception("Invalid tree")

                stack.append(cur)
                cur = eval_expression(cur.GetNonSyntheticValue().Dereference(), left_expression, None)

            cur = stack.pop()
            cache.append(cur.GetNonSyntheticValue().Dereference())
            idx += 1

            cur = eval_expression(cur.GetNonSyntheticValue().Dereference(), right_expression, None)

        if size is None:
            if _get_ptr_value(cur) != 0 and check_condition(cur) or stack and idx >= max_size:
                has_more = True
        else:
            if idx < size:
                cache.extend([None] * (size - idx))

        self.cache = cache
        self.has_more = has_more
        self.names = None
        self.name2index = None


class BinaryTreeCustomNamesNodesProvider(NodesProvider):
    def __init__(self, size, head_pointer, left_expression, right_expression, node_condition, custom_value_name,
                 wildcards):
        super(BinaryTreeCustomNamesNodesProvider, self).__init__()

        cache = []
        has_more = False
        names = []
        name2index = {}

        # iterate all list nodes and cache them
        max_size = size if size is not None else g_max_num_children
        idx = 0
        cur = head_pointer
        stack = []  # parents

        def check_condition(node):
            if node_condition is None:
                return True
            return _check_condition(node.GetNonSyntheticValue().Dereference(), node_condition)

        while (_get_ptr_value(cur) != 0 and check_condition(cur) or stack) and idx < max_size:
            while _get_ptr_value(cur) != 0 and check_condition(cur):
                if len(stack) > 100:  # ~2^100 nodes can't be true - something went wrong
                    raise Exception("Invalid tree")

                stack.append(cur)
                cur = eval_expression(cur.GetNonSyntheticValue().Dereference(), left_expression, None)

            cur = stack.pop()
            cur_val = cur.GetNonSyntheticValue().Dereference()
            name = _evaluate_interpolated_string(custom_value_name, cur_val, wildcards)
            names.append(name)
            name2index[name] = idx
            cache.append(cur_val)
            idx += 1

            cur = eval_expression(cur_val, right_expression, None)

        if size is None:
            if _get_ptr_value(cur) != 0 and check_condition(cur) or stack and idx >= max_size:
                has_more = True
        else:
            if idx < size:
                cache.extend([None] * (size - idx))

        self.cache = cache
        self.has_more = has_more
        self.names = names
        self.name2index = name2index


def _node_processor_tree_items_head_pointer(head_pointer_node, ctx_val, wildcards):
    assert isinstance(head_pointer_node, TypeVizItemTreeHeadPointerTypeNode)
    expression = _resolve_wildcards(head_pointer_node.text, wildcards)
    return eval_expression(ctx_val, expression, None)


@optional_node_processor
def _node_processor_tree_items(tree_node, ctx_val, wildcards):
    assert isinstance(tree_node, TypeVizItemProviderTreeItems)
    if tree_node.condition:
        if not _process_node_condition(tree_node.condition, ctx_val, wildcards):
            return None

    size = _find_first_good_node(_node_processor_size, tree_node.size_nodes, ctx_val, wildcards)
    # size can be None

    head_pointer_value = _node_processor_tree_items_head_pointer(tree_node.head_pointer_node, ctx_val,
                                                                 wildcards)

    left_pointer_node = tree_node.left_pointer_node
    assert isinstance(left_pointer_node, TypeVizItemTreeChildPointerTypeNode)

    right_pointer_node = tree_node.right_pointer_node
    assert isinstance(right_pointer_node, TypeVizItemTreeChildPointerTypeNode)

    left_pointer_expression = _resolve_wildcards(left_pointer_node.text, wildcards)
    right_pointer_expression = _resolve_wildcards(right_pointer_node.text, wildcards)

    value_node = tree_node.value_node_node
    assert isinstance(value_node, TypeVizItemTreeNodeTypeNode)

    value_expression = _resolve_wildcards(value_node.expr.text, wildcards)
    value_opts = value_node.expr.view_options

    condition = value_node.condition
    value_condition = _resolve_wildcards(condition.condition, wildcards) if condition and condition.condition else None

    if value_node.name is None:
        nodes_provider = BinaryTreeIndexedNodesProvider(size, head_pointer_value,
                                                        left_pointer_expression, right_pointer_expression,
                                                        value_condition)
    else:
        nodes_provider = BinaryTreeCustomNamesNodesProvider(size, head_pointer_value,
                                                            left_pointer_expression, right_pointer_expression,
                                                            value_condition, value_node.name, wildcards)

    return CustomItemsProvider(nodes_provider, value_expression, value_opts, wildcards)


def _process_item_provider_tree_items(tree_node, val, wildcards):
    return _node_processor_tree_items(tree_node, val, wildcards)


class CustomListItemsInstruction(object):
    def __init__(self, next_instruction, condition):
        self.next_instruction = next_instruction
        self.condition = condition

    def evaluate_condition(self, ctx_val: lldb.SBValue, context) -> bool:
        if not self.condition:
            return True
        return _check_condition(ctx_val, self.condition, context)

    def execute(self, ctx_val: lldb.SBValue, context, items_collector: List[lldb.SBValue]):
        return None


class CustomListItemsExecInstruction(CustomListItemsInstruction):
    def __init__(self, code, condition, next_instruction):
        super(CustomListItemsExecInstruction, self).__init__(next_instruction, condition)
        self.code = code

    def execute(self, ctx_val: lldb.SBValue, context, items_collector: List[lldb.SBValue]):
        if self.evaluate_condition(ctx_val, context):
            eval_expression(ctx_val, self.code, None, context)
        return self.next_instruction


class CustomListItemsItemInstruction(CustomListItemsInstruction):
    def __init__(self, name: TypeVizInterpolatedString, expr, opts, condition, next_instruction):
        super(CustomListItemsItemInstruction, self).__init__(next_instruction, condition)
        self.name: TypeVizInterpolatedString = name
        self.expr = expr
        self.opts = opts

    def execute(self, ctx_val: lldb.SBValue, context, items_collector: List[lldb.SBValue]):
        if self.evaluate_condition(ctx_val, context):
            if self.name:
                name = _evaluate_interpolated_string(self.name, ctx_val, context=context)
            else:
                name = "[{}]".format(len(items_collector))

            item = eval_expression(ctx_val, self.expr, name, context)
            if self.opts.array_size:
                size_value = eval_expression(ctx_val, self.opts.array_size, None, context)
                size = size_value.GetValueAsSigned()
            else:
                size = None

            item = _apply_value_formatting(item, self.opts.format_spec, self.opts.format_flags, size,
                                           self.opts.view_spec_id)
            items_collector.append(item)
            return self.next_instruction
        return self.next_instruction


class CustomListItemsIfInstruction(CustomListItemsInstruction):
    def __init__(self, condition, then_instruction, next_instruction):
        super(CustomListItemsIfInstruction, self).__init__(next_instruction, condition)
        self.then_instruction = then_instruction

    def execute(self, ctx_val: lldb.SBValue, context, items_collector: List[lldb.SBValue]):
        if self.evaluate_condition(ctx_val, context):
            return self.then_instruction
        return self.next_instruction


def _process_code_block_nodes(block_nodes, wildcards, next_instr, loop_breaks: List[CustomListItemsInstruction]):
    end_if_instr = None
    for node in reversed(block_nodes):
        if isinstance(node, TypeVizItemExecCodeBlockTypeNode):
            value = _resolve_wildcards(node.value, wildcards)
            condition = _resolve_wildcards(node.condition, wildcards) if node.condition else None
            next_instr = CustomListItemsExecInstruction(value, condition, next_instr)
        elif isinstance(node, TypeVizItemItemCodeBlockTypeNode):
            name = _resolve_wildcards_in_interpolated_string(node.name, wildcards) if node.name else None
            expression = _resolve_wildcards(node.expr.text, wildcards)
            opts = node.expr.view_options
            condition = _resolve_wildcards(node.condition, wildcards) if node.condition else None
            next_instr = CustomListItemsItemInstruction(name, expression, opts, condition, next_instr)
        elif isinstance(node, TypeVizItemIfCodeBlockTypeNode):
            condition = _resolve_wildcards(node.condition, wildcards)
            if not end_if_instr:
                end_if_instr = next_instr
            then_instr = _process_code_block_nodes(node.code_blocks, wildcards, end_if_instr, loop_breaks)
            next_instr = CustomListItemsIfInstruction(condition, then_instr, next_instr)
            end_if_instr = None
        elif isinstance(node, TypeVizItemElseCodeBlockTypeNode):
            end_if_instr = next_instr
            next_instr = _process_code_block_nodes(node.code_blocks, wildcards, next_instr, loop_breaks)
        elif isinstance(node, TypeVizItemElseIfCodeBlockTypeNode):
            condition = _resolve_wildcards(node.condition, wildcards) if node.condition else None
            if not end_if_instr:
                end_if_instr = next_instr
            then_instr = _process_code_block_nodes(node.code_blocks, wildcards, end_if_instr, loop_breaks)
            next_instr = CustomListItemsIfInstruction(condition, then_instr, next_instr)
        elif isinstance(node, TypeVizItemLoopCodeBlockTypeNode):
            condition = _resolve_wildcards(node.condition, wildcards) if node.condition else None
            loop_instr = CustomListItemsIfInstruction(condition, None, next_instr)
            loop_breaks.append(next_instr)
            then_instr = _process_code_block_nodes(node.code_blocks, wildcards, loop_instr, loop_breaks)
            loop_breaks.pop()
            loop_instr.then_instruction = then_instr
            next_instr = loop_instr
        elif isinstance(node, TypeVizItemBreakCodeBlockTypeNode):
            if node.condition and node.condition != "":
                condition = _resolve_wildcards(node.condition, wildcards)
                next_instr = CustomListItemsIfInstruction(condition, loop_breaks[-1], next_instr)
            else:
                next_instr = loop_breaks[-1]

    return next_instr


g_static_counter = 0


def _process_variables_nodes(variable_nodes: List[TypeVizItemVariableTypeNode], wildcards):
    prolog_collection = []
    epilog_collection = []
    first_time_code_collection = []
    code_collection = []
    for node in variable_nodes:
        initial_value = _resolve_wildcards(node.initial_value, wildcards)

        global g_static_counter
        g_static_counter += 1
        persistent_name = "$" + node.name + str(g_static_counter)
        first_time_code_collection.append("auto {} = {};".format(persistent_name, initial_value))
        code_collection.append("{} = {};".format(persistent_name, initial_value))

        prolog_collection.append("auto {} = {};".format(node.name, persistent_name))
        epilog_collection.append("{} = {};".format(persistent_name, node.name))
    prolog = "".join(prolog_collection)
    epilog = "".join(epilog_collection)
    code = "".join(code_collection) + "1"
    first_time_code = "".join(first_time_code_collection) + "1"

    def create_context(ctx_var: lldb.SBValue, first_time: bool):
        options = lldb.SBExpressionOptions()
        eval_expression(ctx_var, first_time_code if first_time else code, options=options)

        return EvaluationContext(prolog, epilog)

    return create_context


class CustomListItemsProvider(AbstractChildrenProvider):
    def __init__(self, instr: CustomListItemsInstruction,
                 size, ctx_val: lldb.SBValue, context: EvaluationContext):
        self.cached_items = list()
        max_size = size if size is not None else g_max_num_children
        while instr and len(self.cached_items) < max_size:
            instr = instr.execute(ctx_val, context, self.cached_items)

        self.size = len(self.cached_items)

        self.name_to_item = dict()
        for i in range(self.size):
            self.name_to_item[self.cached_items[i].GetName()] = i

    def num_children(self):
        return len(self.cached_items)

    def get_child_index(self, name):
        try:
            return self.name_to_item[name]
        except KeyError:
            return INVALID_CHILD_INDEX

    def get_child_at_index(self, index):
        return self.cached_items[index]


g_node_to_evaluation_context_factory = {}


@optional_node_processor
def _node_processor_custom_list_items(tree_node: TypeVizItemProviderCustomListItems, ctx_val: lldb.SBValue, wildcards):
    root_instr = _process_code_block_nodes(tree_node.code_block_nodes, wildcards, None, [])

    if tree_node.condition:
        if not _process_node_condition(tree_node.condition, ctx_val, wildcards):
            return None

    size = _find_first_good_node(_node_processor_size, tree_node.size_nodes, ctx_val, wildcards)
    # size can be None

    instantiated_node = (tree_node, wildcards)
    if instantiated_node not in g_node_to_evaluation_context_factory:
        context_factory = _process_variables_nodes(tree_node.variables_nodes, wildcards)
        g_node_to_evaluation_context_factory[instantiated_node] = context_factory
        context = context_factory(ctx_val, True)
    else:
        context_factory = g_node_to_evaluation_context_factory[instantiated_node]
        context = context_factory(ctx_val, False)

    return CustomListItemsProvider(root_instr, size, ctx_val, context)


def _process_item_provider_custom_list_items(tree_node, val, wildcards):
    return _node_processor_custom_list_items(tree_node, val, wildcards)


def _build_child_providers(item_providers: list,
                           value_non_synth: lldb.SBValue,
                           wildcards: tuple,
                           hide_raw_view: bool) -> list[AbstractChildrenProvider]:
    provider_handlers = {
        TypeVizItemProviderTypeKind.Single: _process_item_provider_single,
        TypeVizItemProviderTypeKind.Expanded: _process_item_provider_expanded,
        TypeVizItemProviderTypeKind.ArrayItems: _process_item_provider_array_items,
        TypeVizItemProviderTypeKind.IndexListItems: _process_item_provider_index_list_items,
        TypeVizItemProviderTypeKind.LinkedListItems: _process_item_provider_linked_list_items,
        TypeVizItemProviderTypeKind.TreeItems: _process_item_provider_tree_items,
        TypeVizItemProviderTypeKind.CustomListItems: _process_item_provider_custom_list_items,
    }
    child_providers = []
    for item_provider in item_providers:
        handler = provider_handlers.get(item_provider.kind)
        if not handler:
            continue
        child_provider = handler(item_provider, value_non_synth, wildcards)
        if not child_provider:
            continue
        child_providers.append(child_provider)

    if not hide_raw_view and (value_non_synth.GetFormat() & eFormatNoRawView) == 0:
        child_providers.append(RawViewItemProvider(value_non_synth))

    return child_providers
