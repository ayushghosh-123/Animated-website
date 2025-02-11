from __future__ import annotations

import threading
import traceback
from enum import Enum
from typing import Optional

import lldb
from jb_declarative_formatters.type_viz import IntrinsicsScope, TypeVizIntrinsic
from renderers.jb_lldb_declarative_formatters_options import set_recursion_level, get_global_intrinsics_context
from renderers.jb_lldb_format_specs import eFormatRawView
from renderers.jb_lldb_logging import log
from renderers.jb_lldb_utils_context_operator_parser import replace_context_operators_in_text
from renderers.jb_lldb_utils_debugger_events_handler import DebuggerEventsHandler
from six import StringIO


class EvaluateError(Exception):
    def __init__(self, error):
        super(Exception, self).__init__(str(error))


class IgnoreSynthProvider(Exception):
    def __init__(self, msg=None):
        super(Exception, self).__init__(str(msg) if msg else None)


class CachedLineOfCodeItemStatus(Enum):
    Unknown = None
    Created = 0
    Succeed = 1
    Error = 2


class AtomicInteger:
    def __init__(self, value: int = 0):
        self._value = value
        self._lock = threading.Lock()

    def reset(self, value: int = 0):
        with self._lock:
            prev = self._value
            self._value = value
            return prev

    def inc(self, d: int = 1):
        with self._lock:
            self._value += d
            return self._value

    @property
    def value(self):
        with self._lock:
            return self._value


g_expr_evaluation_code_cache = {}
g_module_specific_variable_counter = 100
g_modules_count_changes_in_this_debugger_session: AtomicInteger = AtomicInteger()


class CachedLineOfCodeItem:
    const_mark_for_search_code_to_modify: str = '>>$$||<!<!code_for_replace'
    const_end_mark_for_search_code_to_modify: str = '>>||'
    const_default_modified_mark: str = \
        const_mark_for_search_code_to_modify + '0' + const_end_mark_for_search_code_to_modify

    def __init__(self, line_of_code: str, needs_retry_on_fail: bool):
        self.needs_retry_on_fail: bool = needs_retry_on_fail
        self.line_of_code: str = line_of_code
        self.status: CachedLineOfCodeItemStatus = \
            CachedLineOfCodeItemStatus.Created if needs_retry_on_fail else CachedLineOfCodeItemStatus.Succeed
        self.modules_changes_cookie = g_modules_count_changes_in_this_debugger_session.value

    @property
    def is_succeed(self) -> bool:
        assert self.status != CachedLineOfCodeItemStatus.Unknown

        return self.status == CachedLineOfCodeItemStatus.Succeed

    @property
    def line(self) -> str:
        if self.status == CachedLineOfCodeItemStatus.Error:
            self._mutate_line_if_need()

        return self.line_of_code

    def mark_as_succeed(self):
        assert self.status != CachedLineOfCodeItemStatus.Unknown
        self.status = CachedLineOfCodeItemStatus.Succeed

    def mark_as_error(self):
        self.status = CachedLineOfCodeItemStatus.Error
        self.modules_changes_cookie = g_modules_count_changes_in_this_debugger_session.value

    def _mutate_line_if_need(self) -> None:
        actual_cookie__value = g_modules_count_changes_in_this_debugger_session.value
        if self.modules_changes_cookie == actual_cookie__value:
            log("{}: the number of modules has not changed, skip the line mutate. Cookie: {} ",
                __class__.__name__, actual_cookie__value)
            return

        log("{}: the number of modules has changed, let's mutate the line. Cookie: {}!={} ",
            __class__.__name__, self.modules_changes_cookie, actual_cookie__value)

        index = str.find(self.line_of_code, CachedLineOfCodeItem.const_mark_for_search_code_to_modify)
        if index == -1:
            return
        end_index = str.find(self.line_of_code, CachedLineOfCodeItem.const_end_mark_for_search_code_to_modify, index)
        assert end_index != -1

        global g_module_specific_variable_counter

        self.line_of_code = \
            self.line_of_code[:index + len(CachedLineOfCodeItem.const_mark_for_search_code_to_modify)] + \
            str(g_module_specific_variable_counter) + \
            self.line_of_code[end_index:]

        g_module_specific_variable_counter += 1

        self.modules_changes_cookie = actual_cookie__value


class Stream(object):
    def __init__(self, is64bit: bool, initial_level: int):
        self.stream = StringIO()
        self.pointer_format = "0x{:016x}" if is64bit else "0x{:08x}"
        self.length = 0
        self.level = initial_level

    def create_nested(self):
        val = self.__class__(False, self.level)
        val.pointer_format = self.pointer_format
        val.length = self.length
        return val

    def output(self, text):
        self.length += len(text)
        self.stream.write(text)

    def output_object(self, val_non_synth: lldb.SBValue):
        log("Retrieving summary of value named '{}'...", val_non_synth.GetName())

        val_type = val_non_synth.GetType()
        format_spec = val_non_synth.GetFormat()
        use_raw_viz = format_spec & eFormatRawView
        provider = get_viz_descriptor_provider()
        vis_descriptor = provider.get_matched_visualizers(val_type, use_raw_viz)

        self.level += 1
        prev_level = set_recursion_level(self.level)
        try:
            if vis_descriptor is not None:
                try:
                    vis_descriptor.output_summary(val_non_synth, self)
                except Exception as e:
                    log('Internal error: {}, traceback: {}', str(e), traceback.format_exc())

            else:
                self._output_object_fallback(provider, val_non_synth, val_type)
        finally:
            set_recursion_level(prev_level)
            self.level -= 1

    def _output_object_fallback(self, provider, val_non_synth, val_type):
        # force use raw vis descriptor
        vis_descriptor = provider.get_matched_visualizers(val_type, True)
        if vis_descriptor is not None:
            try:
                vis_descriptor.output_summary(val_non_synth, self)
            except Exception as e:
                log('Internal error: {}', str(e))
        else:
            summary_value = val_non_synth.GetValue() or ''
            self.output(summary_value)

    def output_string(self, text: str):
        self.output(text)

    def output_keyword(self, text: str):
        self.output(text)

    def output_number(self, text: str):
        self.output(text)

    def output_comment(self, text: str):
        self.output(text)

    def output_value(self, text: str):
        self.output(text)

    def output_address(self, address: int):
        self.output_comment(self.pointer_format.format(address))

    def __str__(self):
        return self.stream.getvalue()


INVALID_CHILD_INDEX = 2 ** 32 - 1


class AbstractChildrenProvider(object):
    def num_children(self):
        return 0

    def get_child_index(self, name):
        return INVALID_CHILD_INDEX

    def get_child_at_index(self, index):
        return None


g_empty_children_provider = AbstractChildrenProvider()


class AbstractVisDescriptor(object):
    def output_summary(self, value_non_synth: lldb.SBValue, stream: Stream):
        pass

    def prepare_children(self, value_non_synth: lldb.SBValue) -> AbstractChildrenProvider:
        return g_empty_children_provider


class AbstractVizDescriptorProvider(object):
    def get_matched_visualizers(self, value_type: lldb.SBType, raw_visualizer: bool) -> AbstractVisDescriptor:
        pass


g_viz_descriptor_provider: AbstractVizDescriptorProvider


def get_viz_descriptor_provider() -> AbstractVizDescriptorProvider:
    return g_viz_descriptor_provider


def set_viz_descriptor_provider(provider: AbstractVizDescriptorProvider):
    global g_viz_descriptor_provider
    g_viz_descriptor_provider = provider


class FormattedStream(Stream):
    def output_string(self, text):
        self.stream.write("\xfeS")
        self.output(text)
        self.stream.write("\xfeE")

    def output_keyword(self, text):
        self.stream.write("\xfeK")
        self.output(text)
        self.stream.write("\xfeE")

    def output_number(self, text):
        self.stream.write("\xfeN")
        self.output(text)
        self.stream.write("\xfeE")

    def output_comment(self, text):
        self.stream.write("\xfeC")
        self.output(text)
        self.stream.write("\xfeE")

    def output_value(self, text):
        self.stream.write("\xfeV")
        self.output(text)
        self.stream.write("\xfeE")


def make_absolute_name(root, name):
    return '.'.join([root, name])


def register_lldb_commands(debugger, cmd_map):
    for func, cmd in cmd_map.items():
        debugger.HandleCommand('command script add -f {func} {cmd}'.format(func=func, cmd=cmd))


class EvaluationContext(object):
    def __init__(self, prolog: str, epilog: str):
        self.prolog_code: str = prolog
        self.epilog_code: str = epilog

    def __hash__(self):
        return hash((self.prolog_code, self.epilog_code))


def _expand_modules_context_operators(code: str) -> CachedLineOfCodeItem:
    is_context_operator_exists = False

    def replace(module, identifier):
        # do we need escape 'module'? '"' can cause problems, but it's very rarely case
        nonlocal is_context_operator_exists

        is_context_operator_exists = True
        default_modified_mark = CachedLineOfCodeItem.const_default_modified_mark
        substitution = \
            f'\n' \
            f'#pragma x__jb__context_operator(module, "{module}") // {default_modified_mark}\n' \
            f'{identifier}'
        return substitution

    expanded_code = replace_context_operators_in_text(code, replace)
    return CachedLineOfCodeItem(expanded_code, needs_retry_on_fail=is_context_operator_exists)


def _execute_code_line(code_line: CachedLineOfCodeItem,
                       ctx_var: lldb.SBValue,
                       options_local: lldb.SBExpressionOptions,
                       lldb_value_name: Optional[str]) -> lldb.SBValue:
    expr = _add_intrinsics_prolog(ctx_var, code_line.line)

    result = _execute_lldb_eval(ctx_var, expr, options_local, lldb_value_name)

    if code_line.is_succeed:
        return result

    error = result.GetError()
    if error.Fail():
        code_line.mark_as_error()

        log("Init scripts evaluate failed: {}", str(error))
        raise EvaluateError(error)

    code_line.mark_as_succeed()

    return result


def _prepare_code_for_eval(expr: str, context: EvaluationContext):
    cached = g_expr_evaluation_code_cache.get((expr, context), None)
    if cached is not None:
        return cached()

    prepared_code = _process_builtin_intrinsics_and_context_operators(context, expr)

    def eval_func_fabric():
        def eval_func(ctx_var: lldb.SBValue, eval_options: lldb.SBExpressionOptions,
                      value_name: Optional[str]) -> lldb.SBValue:

            if eval_options is not None:
                options_local = eval_options
            else:
                options_local = _prepare_default_lldb_expression_options()

            eval_result = _execute_code_line(prepared_code, ctx_var, options_local, value_name)

            return eval_result

        return eval_func

    g_expr_evaluation_code_cache[(expr, context)] = eval_func_fabric

    return eval_func_fabric()


def _prepare_default_lldb_expression_options():
    options = lldb.SBExpressionOptions()
    options.SetSuppressPersistentResult(True)
    options.SetFetchDynamicValue(lldb.eDynamicDontRunTarget)
    return options


def _process_builtin_intrinsics_and_context_operators(context: EvaluationContext, expr: str) -> CachedLineOfCodeItem:
    if "__findnonnull" in expr:
        find_non_null = """#define __findnonnull(PTR, SIZE) [&](decltype(PTR) ptr, decltype(SIZE) size){\\
                for (int i = 0; i < size; ++ i)\\
                    if (ptr[i] != nullptr)\\
                        return i;\\
                return -1;\\
            }(PTR, SIZE)
            """
    else:
        find_non_null = ""
    if context and (context.prolog_code or context.epilog_code):
        format_string = "{}{}; auto&& __lldb__result__ = ({}); {}; __lldb__result__;"
        code = format_string.format(find_non_null, context.prolog_code, expr, context.epilog_code)
    elif find_non_null != "":
        code = find_non_null + expr
    else:
        code = expr

    return _expand_modules_context_operators(code)


def _execute_lldb_eval(val: lldb.SBValue, code: str, options: lldb.SBExpressionOptions,
                       lldb_value_name: Optional[str]) -> lldb.SBValue:
    result = val.EvaluateExpression(code, options, lldb_value_name)
    if result is None:
        err = lldb.SBError()
        err.SetErrorString("evaluation setup failed")
        log("Evaluate failed: {}", str(err))
        raise EvaluateError(err)
    return result


g_intrinsics_prolog = dict[str, tuple[str, int]]()


def _prepare_intrinsics_prolog(val: lldb.SBValue) -> str:
    prolog = ''
    context = get_global_intrinsics_context()
    if not context or (not context.global_intrinsic_scope and not context.type_intrinsic_scope):
        return prolog

    def build_prolog_from_intrinsic_list(intrinsic_list: list[TypeVizIntrinsic]) -> str:
        result = '\n'.join([intrinsic.get_definition_code() for intrinsic in intrinsic_list])
        return result

    def validate_error(result: lldb.SBValue) -> tuple[bool, Optional[lldb.SBError]]:
        if result is None:
            err = lldb.SBError()
            err.SetErrorString("Evaluation setup failed")
            return False, err
        error = result.GetError()
        if error.Fail():
            return False, error

        return True, None

    def fill_intrinsic_list_from_scope(
      lldb_val: lldb.SBValue,
      scope: IntrinsicsScope,
      skip_unused: bool,
      result_intrinsics: list[TypeVizIntrinsic]) -> None:

        if not scope:
            return

        for intrinsic in scope.sorted_list:
            if skip_unused and not intrinsic.is_used:
                continue  # like VS, we can skip the global intrinsic

            dependencies_init_code = build_prolog_from_intrinsic_list(result_intrinsics)
            intrinsic_check_code = intrinsic.get_code_for_validate(dependencies_init_code)
            if not intrinsic_check_code:
                continue

            eval_result_epilog = "; 1"

            code = intrinsic_check_code + eval_result_epilog
            result: lldb.SBValue = lldb_val.EvaluateExpression(code, _prepare_default_lldb_expression_options())

            success, error = validate_error(result)
            if not success:
                type_name = lldb_val.GetTypeName()
                if intrinsic.optional:
                    log("Ignoring error on evaluating optional the intrinsic '{}' with expression '{}' on object '{}'."
                        " Error: {}",
                        intrinsic.name, intrinsic.expression, type_name, str(error))
                    continue
                log("Error on evaluating the intrinsic '{}' with expression '{}' on object '{}'. Error: {}",
                    intrinsic.name, intrinsic.expression, type_name, str(error))
                raise EvaluateError(error)

            replaced = False
            for idx, item in enumerate(result_intrinsics):
                if intrinsic.name == item.name:
                    result_intrinsics[idx] = intrinsic
                    replaced = True
            if not replaced:
                result_intrinsics.append(intrinsic)

    type_intrinsics: list[TypeVizIntrinsic] = []

    fill_intrinsic_list_from_scope(val, context.global_intrinsic_scope,
                                   skip_unused=True, result_intrinsics=type_intrinsics)
    fill_intrinsic_list_from_scope(val, context.type_intrinsic_scope,
                                   skip_unused=False, result_intrinsics=type_intrinsics)

    prolog = build_prolog_from_intrinsic_list(type_intrinsics)

    return prolog


def _add_intrinsics_prolog(val: lldb.SBValue, expression: str) -> str:
    actual_modules_changes_cookie = g_modules_count_changes_in_this_debugger_session.value

    type_hex_name = val.GetTypeName().encode('utf-8').hex()
    intrinsic_prolog, modules_changes_cookie = g_intrinsics_prolog.get(type_hex_name, (None, None))

    if intrinsic_prolog is None or modules_changes_cookie != actual_modules_changes_cookie:
        intrinsic_prolog = _prepare_intrinsics_prolog(val)

        g_intrinsics_prolog[type_hex_name] = (intrinsic_prolog, g_modules_count_changes_in_this_debugger_session.value)

    if intrinsic_prolog:
        return f"{intrinsic_prolog}\n" \
               f"\n" \
               f"{expression}"

    return expression


def eval_expression(val: lldb.SBValue, expr: str, value_name: Optional[str] = None,
                    context: Optional[EvaluationContext] = None,
                    options: lldb.SBExpressionOptions = None) -> lldb.SBValue:
    log("Evaluate '{}' in context of '{}' of type '{}'", expr, val.GetName(), val.GetTypeName())

    eval_func = _prepare_code_for_eval(expr, context)

    eval_result = eval_func(val, options, value_name)

    result_non_synth = eval_result.GetNonSyntheticValue()
    err: lldb.SBError = result_non_synth.GetError()
    if err.Fail():
        err_type = err.GetType()
        err_code = err.GetError()
        if err_type == lldb.eErrorTypeExpression and err_code == lldb.eExpressionParseError:
            log("Evaluate failed (can't parse expression): {}", str(err))
            raise EvaluateError(err)

        # error is runtime error which is handled later
        log("Returning value with error: {}", str(err))
        return eval_result

    log("Evaluate succeed: result type - {}", str(result_non_synth.GetTypeName()))
    return eval_result


def get_root_value(val: lldb.SBValue) -> lldb.SBValue:
    val_non_synth: lldb.SBValue = val.GetNonSyntheticValue()
    val_non_synth.SetPreferDynamicValue(lldb.eNoDynamicValues)
    return val_non_synth


def get_value_format(val: lldb.SBValue) -> int:
    return get_root_value(val).GetFormat()


def set_value_format(val: lldb.SBValue, fmt: int):
    # noinspection PyArgumentList
    get_root_value(val).SetFormat(fmt)


def invalidate_cache_on_restart_debugger() -> None:
    global g_expr_evaluation_code_cache
    g_expr_evaluation_code_cache = {}

    g_modules_count_changes_in_this_debugger_session.reset()


g_debugger_events_handler: DebuggerEventsHandler | None = None


def modules_count_changed() -> None:
    new_value = g_modules_count_changes_in_this_debugger_session.inc()

    log("Modules count changes from {} to {}", new_value - 1, new_value)


def start_listener(debugger: lldb.SBDebugger) -> None:
    global g_debugger_events_handler

    stop_listener()

    g_debugger_events_handler = DebuggerEventsHandler(debugger)
    g_debugger_events_handler.add_target_handler(modules_count_changed)


def stop_listener() -> None:
    global g_debugger_events_handler

    if g_debugger_events_handler is None:
        return

    g_debugger_events_handler.stop()
    g_debugger_events_handler = None
