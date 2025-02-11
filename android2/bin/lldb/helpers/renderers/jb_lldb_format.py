import lldb
from renderers.jb_lldb_format_specs import *
from renderers.jb_lldb_utils import get_root_value, get_value_format


def overlay_child_format(child: lldb.SBValue, parent_spec: int):
    child_root = get_root_value(child)
    child_spec = child_root.GetFormat()

    basic_specs = child_spec & eFormatBasicSpecsMask
    parent_basic_specs = parent_spec & eFormatBasicSpecsMask
    # TODO: more complex logic to merge basic specs
    if basic_specs == 0:
        basic_specs = parent_basic_specs

    flag_specs = (child_spec & eFormatFlagSpecsMask) | \
                 (parent_spec & eFormatFlagSpecsMask & eFormatInheritedFlagsMask)

    custom_view_spec = get_custom_view_id(child_spec)

    fmt = set_custom_view_id(basic_specs | flag_specs, custom_view_spec)
    child_root.SetFormat(fmt)


def overlay_summary_format(child: lldb.SBValue, parent_non_synth: lldb.SBValue):
    child_root = get_root_value(child)
    child_spec = child_root.GetFormat()
    parent_spec = parent_non_synth.GetFormat()

    basic_specs = child_spec & eFormatBasicSpecsMask
    parent_basic_specs = parent_spec & eFormatBasicSpecsMask

    if basic_specs == 0:
        basic_specs = parent_basic_specs
    elif basic_specs in FMT_UNQUOTE_MAP and parent_basic_specs in FMT_STRING_NOQUOTES_SET:
        # special case for FName
        basic_specs = FMT_UNQUOTE_MAP[basic_specs]

    flag_specs = (child_spec & eFormatFlagSpecsMask) | \
                 (parent_spec & eFormatFlagSpecsMask & eFormatInheritedFlagsMask)

    custom_view_spec = get_custom_view_id(child_spec)

    fmt = set_custom_view_id(basic_specs | flag_specs, custom_view_spec)
    if parent_spec & eFormatAsArray != 0 and child_spec & eFormatAsArray == 0:
        fmt |= eFormatAsArray
        size = parent_non_synth.GetFormatAsArraySize()
        child_root.SetFormatAsArraySize(size)

    child_root.SetFormat(fmt)


def update_value_dynamic_state(value: lldb.SBValue):
    fmt = get_value_format(value)
    if fmt & eFormatNoDerived:
        value.SetPreferDynamicValue(lldb.eNoDynamicValues)
