import re
from collections import defaultdict
from typing import List, TypeVar, Callable

import six
from jb_declarative_formatters import TypeViz, TypeVizName
from jb_declarative_formatters.type_name_template import TypeNameTemplate

TVertex = TypeVar("TVertex")


class DirectAcyclicGraph(object):
    def __init__(self, vertices: List[TVertex], children_accessor: Callable[[TVertex], list[TVertex]]):
        self.children_accessor = children_accessor
        self.vertices = vertices

    def _inner_recursive_sort(self, v: TVertex, visited: set[TVertex], stack: list[TVertex]) -> None:
        visited.add(v)
        for c in self.children_accessor(v):
            if c not in visited:
                self._inner_recursive_sort(c, visited, stack)

        stack.append(v)

    def sort(self) -> list[TVertex]:
        visited = set[TVertex]()
        accumulator = list[TVertex]()
        for v in self.vertices:
            if v not in visited:
                self._inner_recursive_sort(v, visited, accumulator)
        return accumulator


class TypeVizDescriptor(object):
    def __init__(self, type_viz_name: TypeVizName, regex: str, visualizer: TypeViz):
        self.name = type_viz_name
        self.regex = regex
        self.visualizers: List[TypeViz] = [visualizer]
        self.more_specific_descriptors = []

    def __str__(self):
        return str(self.name)


class TypeVizStorage(object):
    class Item(object):
        def __init__(self):
            self.descriptors_was_sorted: bool = False
            self.exact_match: List[TypeVizDescriptor] = []
            self.wildcard_match: List[TypeVizDescriptor] = []

        def ensure_descriptors_sorted(self):
            if self.descriptors_was_sorted:
                return

            for descriptor in self.exact_match:
                descriptor.visualizers.sort(key=lambda x: -x.priority)

            for descriptor in self.wildcard_match:
                descriptor.visualizers.sort(key=lambda x: -x.priority)

            graph = DirectAcyclicGraph(self.wildcard_match, lambda m: m.more_specific_descriptors)
            self.wildcard_match = list(graph.sort())
            self.descriptors_was_sorted = True

    def __init__(self, logger=None):
        self._logger = logger
        self._types = defaultdict(TypeVizStorage.Item)

    def add_type(self, type_viz: TypeViz):
        for type_viz_name in type_viz.type_viz_names:
            key: str = _build_key(type_viz_name.type_name_template)
            if type_viz_name.has_wildcard:
                regex = "^" + _build_regex(type_viz_name.type_name_template) + "$"
                item = self._types[key]
                item.descriptors_was_sorted = False

                descriptor_found = False
                for descriptor in item.wildcard_match:
                    if descriptor.regex == regex:
                        descriptor.visualizers.append(type_viz)
                        descriptor_found = True
                        break

                if descriptor_found:
                    continue

                descriptor_to_add = TypeVizDescriptor(type_viz_name, regex, type_viz)
                for descriptor in item.wildcard_match:
                    if descriptor.name.type_name_template.match(type_viz_name.type_name_template, None, None):
                        descriptor.more_specific_descriptors.append(descriptor_to_add)
                    elif type_viz_name.type_name_template.match(descriptor.name.type_name_template, None, None):
                        descriptor_to_add.more_specific_descriptors.append(descriptor)

                item.wildcard_match.append(descriptor_to_add)
            else:
                type_name = str(type_viz_name.type_name_template)
                item = self._types[key]
                item.descriptors_was_sorted = False
                descriptor_found = False
                for descriptor in item.exact_match:
                    if descriptor.regex == type_name:
                        descriptor.visualizers.append(type_viz)
                        descriptor_found = True
                        break

                if descriptor_found:
                    continue

                descriptor_to_add = TypeVizDescriptor(type_viz_name, type_name, type_viz)
                item.exact_match.append(descriptor_to_add)

    def iterate_exactly_matched_type_viz(self):
        for item in six.itervalues(self._types):
            item.ensure_descriptors_sorted()
            for descriptor in item.exact_match:
                for visualizer in descriptor.visualizers:
                    yield descriptor.regex, visualizer, descriptor.name

    def iterate_wildcard_matched_type_viz(self):
        for item in six.itervalues(self._types):
            item.ensure_descriptors_sorted()
            for descriptor in item.wildcard_match:
                for visualizer in descriptor.visualizers:
                    yield descriptor.regex, visualizer, descriptor.name

    def get_matched_types(self, type_name_template):
        key = _build_key(type_name_template)
        item = self._types.get(key)
        if item:
            item.ensure_descriptors_sorted()
            req_type_name = str(type_name_template)
            for match in item.exact_match:
                if req_type_name == match.regex:
                    for visualizer in match.visualizers:
                        yield visualizer, match.name

            for match in item.wildcard_match:
                wildcard = match.name.type_name_template
                if wildcard.match(type_name_template, None, self._logger):
                    for visualizer in match.visualizers:
                        yield visualizer, match.name


def _build_key(type_name_template: TypeNameTemplate):
    idx_prefix_end = type_name_template.name.find('<')
    if idx_prefix_end == -1:
        return type_name_template.name
    return type_name_template.name[:idx_prefix_end]


def _build_regex(type_name_template):
    if type_name_template.is_wildcard:
        return '(.*)'
    if not type_name_template.args:
        return re.escape(type_name_template.name)
    return type_name_template.fmt.format(*[_build_regex(arg) for arg in type_name_template.args])
