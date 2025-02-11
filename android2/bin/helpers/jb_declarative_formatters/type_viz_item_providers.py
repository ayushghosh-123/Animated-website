from enum import Enum, auto
from typing import List

from jb_declarative_formatters.type_viz_item_nodes import TypeVizItemSizeTypeNode, TypeVizItemTreeHeadPointerTypeNode, \
    TypeVizItemTreeChildPointerTypeNode, TypeVizItemTreeNodeTypeNode, TypeVizItemVariableTypeNode, \
    TypeVizItemListItemsIndexNodeTypeNode, TypeVizItemListItemsHeadPointerTypeNode, \
    TypeVizItemListItemsNextPointerTypeNode, TypeVizItemIndexNodeTypeNode, TypeVizItemValuePointerTypeNode
from jb_declarative_formatters.type_viz_mixins import \
    TypeVizItemFormattedExpressionNodeMixin, \
    TypeVizItemNamedNodeMixin, \
    TypeVizItemConditionalNodeMixin, \
    TypeVizItemOptionalNodeMixin


class TypeVizItemProviderTypeKind(Enum):
    Single = auto(),
    Expanded = auto(),
    # Synthetic = auto(),
    ArrayItems = auto(),
    IndexListItems = auto(),
    LinkedListItems = auto(),
    TreeItems = auto(),
    CustomListItems = auto()


class TypeVizItemProviderSingle(TypeVizItemFormattedExpressionNodeMixin,
                                TypeVizItemNamedNodeMixin,
                                TypeVizItemConditionalNodeMixin,
                                TypeVizItemOptionalNodeMixin):
    kind = TypeVizItemProviderTypeKind.Single

    def __init__(self, name, expr, condition, optional):
        super(TypeVizItemProviderSingle, self).__init__(
            expr=expr, name=name, condition=condition,
            optional=optional)


class TypeVizItemProviderExpanded(TypeVizItemFormattedExpressionNodeMixin,
                                  TypeVizItemConditionalNodeMixin,
                                  TypeVizItemOptionalNodeMixin):
    kind = TypeVizItemProviderTypeKind.Expanded

    def __init__(self, expr, condition, optional):
        super(TypeVizItemProviderExpanded, self).__init__(
            expr=expr, condition=condition, optional=optional)


class TypeVizItemProviderArrayItems(TypeVizItemConditionalNodeMixin,
                                    TypeVizItemOptionalNodeMixin):
    kind = TypeVizItemProviderTypeKind.ArrayItems

    def __init__(self, size_nodes, value_pointer_nodes, condition, optional):
        super(TypeVizItemProviderArrayItems, self).__init__(
            condition=condition, optional=optional)
        self.size_nodes: List[TypeVizItemSizeTypeNode] = size_nodes
        self.value_pointer_nodes: List[TypeVizItemValuePointerTypeNode] = value_pointer_nodes


class TypeVizItemProviderIndexListItems(TypeVizItemConditionalNodeMixin,
                                        TypeVizItemOptionalNodeMixin):
    kind = TypeVizItemProviderTypeKind.IndexListItems

    def __init__(self, size_nodes, value_node_nodes, condition, optional):
        super(TypeVizItemProviderIndexListItems, self).__init__(
            condition=condition, optional=optional)
        self.size_nodes: List[TypeVizItemSizeTypeNode] = size_nodes
        self.value_node_nodes: List[TypeVizItemIndexNodeTypeNode] = value_node_nodes


class TypeVizItemProviderLinkedListItems(TypeVizItemConditionalNodeMixin,
                                         TypeVizItemOptionalNodeMixin):
    kind = TypeVizItemProviderTypeKind.LinkedListItems

    def __init__(self, size_nodes, head_pointer_node, next_pointer_node,
                 value_node_node, condition, optional):
        super(TypeVizItemProviderLinkedListItems, self).__init__(
            condition=condition, optional=optional)
        self.size_nodes: List[TypeVizItemSizeTypeNode] = size_nodes
        self.head_pointer_node: TypeVizItemListItemsHeadPointerTypeNode = head_pointer_node
        self.next_pointer_node: TypeVizItemListItemsNextPointerTypeNode = next_pointer_node
        self.value_node_node: TypeVizItemListItemsIndexNodeTypeNode = value_node_node


class TypeVizItemProviderTreeItems(TypeVizItemConditionalNodeMixin,
                                   TypeVizItemOptionalNodeMixin):
    kind = TypeVizItemProviderTypeKind.TreeItems

    def __init__(self, size_nodes, head_pointer_node,
                 left_pointer_node, right_pointer_node, value_node_node,
                 condition, optional):
        super(TypeVizItemProviderTreeItems, self).__init__(
            condition=condition, optional=optional)
        self.size_nodes: List[TypeVizItemSizeTypeNode] = size_nodes
        self.head_pointer_node: TypeVizItemTreeHeadPointerTypeNode = head_pointer_node
        self.left_pointer_node: TypeVizItemTreeChildPointerTypeNode = left_pointer_node
        self.right_pointer_node: TypeVizItemTreeChildPointerTypeNode = right_pointer_node
        self.value_node_node: TypeVizItemTreeNodeTypeNode = value_node_node


class TypeVizItemProviderCustomListItems(TypeVizItemConditionalNodeMixin,
                                         TypeVizItemOptionalNodeMixin):
    kind = TypeVizItemProviderTypeKind.CustomListItems

    def __init__(self, variables_nodes, size_nodes,
                 code_block_nodes, condition, optional):
        super(TypeVizItemProviderCustomListItems, self).__init__(
            condition=condition, optional=optional)
        self.variables_nodes: List[TypeVizItemVariableTypeNode] = variables_nodes
        self.size_nodes: List[TypeVizItemSizeTypeNode] = size_nodes
        self.code_block_nodes: List = code_block_nodes
