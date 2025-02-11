from __future__ import annotations

import abc
import re

from jb_declarative_formatters.type_name_template import TypeNameTemplate
from jb_declarative_formatters.type_viz_expression import get_custom_view_spec_id_by_name
from lldb.formatters.Logger import Logger


class TypeVizName(object):
    def __init__(self, type_name: str, type_name_template: TypeNameTemplate):
        self.type_name: str = type_name
        self.type_name_template: TypeNameTemplate = type_name_template

    @property
    def has_wildcard(self) -> bool:
        return self.type_name_template.has_wildcard

    def __str__(self) -> str:
        return self.type_name


def _format_intrinsic_name(name: str, parameters_count: int):
    return f"__{name}___{parameters_count}__"


def create_intrinsic(intrinsic_overloads: dict[str, int],
                     name: str, expression: str, optional: bool,
                     parameters: list[TypeVizIntrinsicParameter],
                     dependencies: list[IntrinsicCall]):
    if len(parameters) == 0 and intrinsic_overloads[name] == 1:
        return TypeVizIntrinsicInlined(
            name, expression,
            optional, parameters,
            dependencies)
    else:
        return TypeVizIntrinsicLambdaBased(
            name, expression,
            optional, parameters,
            dependencies)


class IntrinsicsScope:
    def __init__(self, sorted_list: list[TypeVizIntrinsic], intrinsic_scope_name: str):
        self.sorted_list = sorted_list
        self.intrinsic_scope_name = intrinsic_scope_name
        self.name_to_indexes_map: dict[str, list[int]] = {}

        for i in range(len(sorted_list)):
            name = sorted_list[i].name
            if name not in self.name_to_indexes_map:
                self.name_to_indexes_map[name] = list[int]()
            self.name_to_indexes_map[name].append(i)

    def retain_only_lazy(self) -> IntrinsicsScope:
        new_list = [item for item in self.sorted_list if item.is_lazy]
        return IntrinsicsScope(new_list, self.intrinsic_scope_name)


class IntrinsicCall(object):
    def __init__(self, name: str, args_count: int, args_begin_pos: int, args_end_pos: int):
        self.args_end_pos = args_end_pos
        self.args_begin_pos = args_begin_pos
        self.args_count = args_count
        self.base_name = name
        self.name = _format_intrinsic_name(self.base_name, self.args_count)


class TypeVizIntrinsicParameter(object):
    def __init__(self, parameter_name: str | None, parameter_type: str):
        self.parameter_type = parameter_type
        self.parameter_name = parameter_name


class TypeVizIntrinsic(abc.ABC):
    def __init__(self, name: str, expression: str, optional: bool,
                 parameters: list[TypeVizIntrinsicParameter],
                 dependencies: list[IntrinsicCall]):
        self.parameters = parameters
        self.base_name: str = name
        self.optional = optional
        self.name: str = _format_intrinsic_name(self.base_name, len(self.parameters))
        self.expression: str = expression
        self.original_expression: str = expression
        self.dependencies = dependencies
        self.is_used = False
        self.unique_dependencies = set[str]()
        for dep in self.dependencies:
            self.unique_dependencies.add(dep.name)
        self.is_lazy = True

    def __hash__(self):
        return hash((self.original_expression, self.name, self.optional))

    def change_expression(self, new_expression: str):
        self.expression = new_expression

    def mark_as_used(self):
        self.is_used = True

    @abc.abstractmethod
    def get_intrinsic_call_replacement(self,
                                       expression: str, intrinsic_call: IntrinsicCall,
                                       intrinsic_scope_name: str) -> tuple[str, int, int]:
        pass

    @abc.abstractmethod
    def get_code_for_validate(self, prolog: str) -> str:
        pass

    @abc.abstractmethod
    def get_definition_code(self) -> str:
        pass


class TypeVizIntrinsicInlined(TypeVizIntrinsic):

    def __init__(self, name: str, expression: str, optional: bool,
                 parameters: list[TypeVizIntrinsicParameter],
                 dependencies: list[IntrinsicCall]):
        super().__init__(name, expression, optional, parameters, dependencies)
        self.is_lazy = False

    def get_intrinsic_call_replacement(self,
                                       expression: str, intrinsic_call: IntrinsicCall,
                                       intrinsic_scope_name: str) -> tuple[str, int, int]:
        name_len = len(self.base_name)
        start_pos = intrinsic_call.args_begin_pos - name_len - 1
        end_pos = intrinsic_call.args_end_pos
        text = f"(" \
               f"/*intrinsic_inlined_start {intrinsic_scope_name}:{self.base_name}*/" \
               f'{self.expression}' \
               f"/*{self.base_name} intrinsic_inlined_end*/" \
               f")"

        return text, start_pos, end_pos

    def get_definition_code(self) -> str:
        return ''

    def get_code_for_validate(self, prolog: str) -> str:
        return ''


class TypeVizIntrinsicLambdaBased(TypeVizIntrinsic):

    def __init__(self, name: str, expression: str, optional: bool,
                 parameters: list[TypeVizIntrinsicParameter],
                 dependencies: list[IntrinsicCall]):
        super().__init__(name, expression, optional, parameters, dependencies)

    def get_intrinsic_call_replacement(self,
                                       expression: str, intrinsic_call: IntrinsicCall,
                                       intrinsic_scope_name: str) -> tuple[str, int, int]:
        name_len = len(self.base_name)
        start_pos = intrinsic_call.args_begin_pos - name_len - 1
        end_pos = intrinsic_call.args_begin_pos
        text = f"JB_MACRO_{self.name}("

        return text, start_pos, end_pos

    def get_code_for_validate(self, prolog: str) -> str:
        param_str = ", ".join([f"{p.parameter_type} {p.parameter_name}" for p in self.parameters])
        lambda_stmt = f"[&]({param_str})" \
                      "{" \
                      f" {prolog} " \
                      f" return {self.expression} ;" \
                      "}"
        return lambda_stmt

    def get_definition_code(self) -> str:
        param_str_without_types = ", ".join([f" {p.parameter_name}" for p in self.parameters])
        expr = self.expression
        for param in self.parameters:
            expr = expr.replace(param.parameter_name, f'(({param.parameter_type}) ({param.parameter_name}))')
        macros = f"\n" \
                 f"#define JB_MACRO_{self.name}({param_str_without_types}) " \
                 f" ( {expr} )\n" \
                 f""
        return macros


global_intrinsic_variable_counter = 42


class TypeVizIntrinsicGroup(object):
    def __init__(self, name: str):
        self._name: str = name
        self._intrinsics = list[TypeVizIntrinsic]()
        self.is_used = False

        global global_intrinsic_variable_counter
        global_intrinsic_variable_counter += 1
        self._variable_name = f'$autovar_for_intrinsic_n{global_intrinsic_variable_counter}_'

        self._expr_text_cache = set[str]()
        self.optional: bool = True
        self.name_regex = re.compile(f"([^a-zA-Z0-9_]+|^){re.escape(name)}\\(\\)")

    def get_variable_name(self) -> str:
        return self._variable_name

    def add_intrinsic(self, intrinsic: TypeVizIntrinsic) -> None:
        assert self._name == intrinsic.name
        if intrinsic.expression in self._expr_text_cache:
            return
        self._intrinsics.append(intrinsic)
        self._expr_text_cache.add(intrinsic.expression)
        self.optional = self.optional and intrinsic.optional

    def get_intrinsics(self) -> list[TypeVizIntrinsic]:
        return self._intrinsics

    def can_be_skipped(self) -> bool:
        return self.optional and not self.is_used

    def mark_as_used(self) -> None:
        self.is_used = True


class TypeViz(object):
    def __init__(self,
                 type_viz_names: list[TypeVizName],
                 is_inheritable: bool,
                 include_view: str,
                 exclude_view: str,
                 priority: int,
                 global_intrinsics: IntrinsicsScope,
                 type_intrinsics: IntrinsicsScope,
                 logger: Logger = None):
        self.logger = logger  # TODO: or stub

        self.type_viz_names = type_viz_names
        self.is_inheritable = is_inheritable
        self.include_view = include_view
        self.include_view_id = get_custom_view_spec_id_by_name(include_view)
        self.exclude_view = exclude_view
        self.exclude_view_id = get_custom_view_spec_id_by_name(exclude_view)
        self.priority = priority
        self.summaries = []
        self.item_providers = None
        self.global_intrinsics = global_intrinsics
        self.type_intrinsics = type_intrinsics
        self.hide_raw_view: bool = False
