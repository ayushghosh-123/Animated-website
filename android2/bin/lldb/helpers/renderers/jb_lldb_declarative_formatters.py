import distutils.util
import importlib
import inspect
import shlex

from jb_declarative_formatters.parsers.type_name_parser import parse_type_name_template
from renderers.jb_lldb_builtin_formatters import *
from renderers.jb_lldb_declarative_formatters_loaders import *
from renderers.jb_lldb_declarative_formatters_manager import *
from renderers.jb_lldb_format import update_value_dynamic_state
from renderers.jb_lldb_logging import get_suppress_errors
from renderers.jb_lldb_natvis_formatters import NatVisDescriptor

lldb_formatters_manager: FormattersManager


def __lldb_init_module(debugger: lldb.SBDebugger, internal_dict):
    log('JetBrains declarative formatters LLDB module registered into {}', str(debugger))

    commands_list = {
        make_absolute_name(__name__, '_cmd_loaders_add'): 'jb_renderers_loaders_add',
        make_absolute_name(__name__, '_cmd_loaders_remove'): 'jb_renderers_loaders_remove',
        make_absolute_name(__name__, '_cmd_loaders_list'): 'jb_renderers_loaders_list',

        make_absolute_name(__name__, '_cmd_load'): 'jb_renderers_load',
        make_absolute_name(__name__, '_cmd_remove'): 'jb_renderers_remove',
        make_absolute_name(__name__, '_cmd_reload'): 'jb_renderers_reload',

        make_absolute_name(__name__, '_cmd_reload_all'): 'jb_renderers_reload_all',
        make_absolute_name(__name__, '_cmd_remove_all'): 'jb_renderers_remove_all',

        make_absolute_name(__name__, '_cmd_override_charset'): 'jb_renderers_override_charset',
        make_absolute_name(__name__, '_cmd_set_markup'): 'jb_renderers_set_markup',
        make_absolute_name(__name__, '_cmd_set_global_hex'): 'jb_renderers_set_global_hex',
    }
    register_lldb_commands(debugger, commands_list)

    summary_func_name = f'{__name__}.declarative_summary'
    synth_class_name = f'{__name__}.DeclarativeSynthProvider'
    debugger.HandleCommand(f'type summary add -v -x ".*" -F {summary_func_name} -e --category jb_formatters')
    debugger.HandleCommand(f'type synthetic add -x ".*" -l {synth_class_name} --category jb_formatters')

    global lldb_formatters_manager
    lldb_formatters_manager = FormattersManager(summary_func_name, synth_class_name)

    viz_provider = VizDescriptorProvider()
    set_viz_descriptor_provider(viz_provider)

    start_listener(debugger)


def _cmd_loaders_add(debugger, command, exe_ctx, result, internal_dict):
    # raise NotImplementedError("jb_renderers_loaders_add is not implemented yet")
    help_message = 'Usage: jb_renderers_loaders_add <loader_tag> <module> <funcname>'
    cmd = shlex.split(command)
    if len(cmd) < 1:
        result.SetError('Loader tag expected.\n{}'.format(help_message))
        return
    tag = cmd[0]
    cmd = cmd[1:]
    if len(cmd) < 1:
        result.SetError('Python module expected.\n{}'.format(help_message))
        return
    module = cmd[0]

    try:
        mod = importlib.import_module(module)
    except Exception as e:
        result.SetError(str(e))
        return

    cmd = cmd[1:]
    if len(cmd) < 1:
        result.SetError('Function name expected.\n{}'.format(help_message))
        return
    func_name = cmd[0]

    funcs = inspect.getmembers(mod, lambda m: inspect.isfunction(m) and m.__name__ == func_name)
    if funcs is None or len(funcs) == 0:
        result.SetError('Can\'t find loader function {} in module {}'.format(func_name, mod))
        return

    if len(funcs) != 1:
        result.SetError('Loader function {} in module {} is ambiguous'.format(func_name, mod))
        return

    _, func = funcs[0]
    type_viz_loader_add(tag, func)


def _cmd_loaders_remove(debugger, command, exe_ctx, result, internal_dict):
    help_message = 'Usage: jb_renderers_loaders_remove <loader_tag>'
    cmd = shlex.split(command)
    if len(cmd) < 1:
        result.SetError('Loader tag expected.\n{}'.format(help_message))
        return

    tag = cmd[0]
    type_viz_loader_remove(tag)


def _cmd_loaders_list(debugger, command, exe_ctx, result, internal_dict):
    lst = type_viz_loader_get_list()
    lst_view = {tag: func.__module__ + '.' + func.__name__ for tag, func in lst.items()}
    result.AppendMessage(str(lst_view))


def _cmd_load(debugger, command, exe_ctx, result, internal_dict):
    help_message = 'Usage: jb_renderers_load tag <loader_tag> <natvis_file_path>...'
    cmd = shlex.split(command)
    if len(cmd) < 1:
        result.SetError('Loader tag expected.\n{}'.format(help_message))
        return
    tag = cmd[0]
    try:
        loader = type_viz_loader_get(tag)
    except KeyError:
        result.SetError('Unknown loader tag {}'.format(tag))
        return

    file_paths = cmd[1:]
    for filepath in file_paths:
        try:
            lldb_formatters_manager.register(filepath, loader)
        except TypeVizLoaderException as e:
            result.SetError('{}'.format(str(e)))
            return


def _cmd_remove(debugger, command, exe_ctx, result, internal_dict):
    help_message = 'Usage: jb_renderers_remove <vis_file_path>...'
    cmd = shlex.split(command)
    if len(cmd) < 1:
        result.SetError('At least one file expected.\n{}'.format(help_message))
        return

    remove_file_list(debugger, cmd)


def _cmd_reload(debugger, command, exe_ctx, result, internal_dict):
    help_message = 'Usage: jb_renderers_reload <vis_file_path>...'
    cmd = shlex.split(command)
    if len(cmd) < 1:
        result.SetError('At least one file expected.\n{}'.format(help_message))
        return

    reload_file_list(debugger, cmd)


def _cmd_remove_all(debugger, command, exe_ctx, result, internal_dict):
    remove_all(debugger)


def _cmd_reload_all(debugger, command, exe_ctx, result, internal_dict):
    reload_all(debugger)


def _cmd_override_charset(debugger, command, exe_ctx, result, internal_dict):
    help_message = 'Usage: jb_renderers_override_charset <charset>'
    cmd = shlex.split(command)
    if len(cmd) != 1:
        result.SetError('Charset name is expected.\n{}'.format(help_message))
        return

    override_locale(cmd[0])


def _cmd_set_markup(debugger, command, exe_ctx, result, internal_dict):
    help_message = 'Usage: jb_renderers_set_markup <value>'
    cmd = shlex.split(command)
    if len(cmd) != 1:
        result.SetError('Boolean value is expected.\n{}'.format(help_message))
        return

    try:
        enable = bool(distutils.util.strtobool(cmd[0]))
    except Exception as e:
        result.SetError('Boolean value is expected.\n{}'.format(help_message))
        return

    enable_disable_formatting(enable)


def _cmd_set_global_hex(debugger, command, exe_ctx, result, internal_dict):
    help_message = 'Usage: jb_renderers_set_global_hex <value> <value>'
    cmd = shlex.split(command)
    if len(cmd) != 2:
        result.SetError('Two boolean values are expected.\n{}'.format(help_message))
        return

    try:
        hex_enable = bool(distutils.util.strtobool(cmd[0]))
        hex_show_both = bool(distutils.util.strtobool(cmd[1]))
    except Exception as e:
        result.SetError('Boolean value is expected.\n{}'.format(help_message))
        return

    set_global_hex(hex_enable)
    set_global_hex_show_both(hex_show_both)


def remove_all(debugger):
    files = lldb_formatters_manager.get_all_registered_files()
    remove_file_list(debugger, files)


def reload_all(debugger):
    files = lldb_formatters_manager.get_all_registered_files()
    reload_file_list(debugger, files)


def remove_file_list(debugger, files):
    for filepath in files:
        lldb_formatters_manager.unregister(filepath)


def reload_file_list(debugger, files):
    for filepath in files:
        lldb_formatters_manager.reload(filepath)


def declarative_summary(val: lldb.SBValue, internal_dict):
    try:
        update_value_dynamic_state(val)
        val_non_synth = val.GetNonSyntheticValue()
        target = val_non_synth.GetTarget()
        is64bit: bool = target.GetAddressByteSize() == 8
        set_max_string_length(get_max_string_summary_length(target.GetDebugger()))
        stream_type = is_enabled_formatting() and FormattedStream or Stream
        stream: Stream = stream_type(is64bit, get_recursion_level())
        stream.output_object(val_non_synth)
        return str(stream)

    except IgnoreSynthProvider:
        return ''
    except:
        if not get_suppress_errors():
            raise
        return ''


class DeclarativeSynthProvider(object):
    def __init__(self, val, internal_dict):
        update_value_dynamic_state(val)
        self.val_non_synth: lldb.SBValue = val.GetNonSyntheticValue()
        self.children_provider: Optional[AbstractChildrenProvider] = None

    def update(self):
        return False

    def has_children(self):
        return self.val_non_synth.MightHaveChildren()

    def ensure_initialized(self):
        if self.children_provider:
            return
        try:
            log("Retrieving children of value named '{}'...", self.val_non_synth.GetName())

            format_spec = self.val_non_synth.GetFormat()
            use_raw_viz = format_spec & eFormatRawView
            provider = get_viz_descriptor_provider()
            vis_descriptor = provider.get_matched_visualizers(self.val_non_synth.GetType(), use_raw_viz)
            if vis_descriptor:
                self.children_provider = vis_descriptor.prepare_children(self.val_non_synth)

        except IgnoreSynthProvider:
            pass
        except Exception as e:
            # some unexpected error happened
            if not get_suppress_errors():
                log("{}", traceback.format_exc())

        if not self.children_provider:
            self.children_provider = StructChildrenProvider(self.val_non_synth)

    def num_children(self):
        self.ensure_initialized()
        return self.children_provider.num_children()

    def get_child_index(self, name):
        self.ensure_initialized()
        return self.children_provider.get_child_index(name)

    def get_child_at_index(self, index):
        self.ensure_initialized()
        return self.children_provider.get_child_at_index(index)


class VizDescriptorProvider(AbstractVizDescriptorProvider):
    def __init__(self):
        self.type_to_visualizer_cache = {}
        self.type_to_raw_view_visualizer_cache = {}

    def get_matched_visualizers(self, value_type: lldb.SBType, raw_visualizer: bool) -> AbstractVisDescriptor:
        if raw_visualizer:
            cache = self.type_to_raw_view_visualizer_cache
            use_natvis = False
        else:
            cache = self.type_to_visualizer_cache
            use_natvis = True

        type_name = value_type.GetName()

        descriptor = cache.get(type_name, None)
        if descriptor is not None:
            return descriptor

        descriptor = _try_get_matched_visualizers(value_type, use_natvis)
        cache[type_name] = descriptor

        return descriptor


def _get_matched_type_visualizers(type_name_template, only_inherited=False):
    result = []
    if only_inherited:
        for type_viz_storage in lldb_formatters_manager.get_all_type_viz():
            result.extend(
                [name_match_pair for name_match_pair in type_viz_storage.get_matched_types(type_name_template) if
                 name_match_pair[0].is_inheritable])
    else:
        for type_viz_storage in lldb_formatters_manager.get_all_type_viz():
            result.extend(
                [name_match_pair for name_match_pair in type_viz_storage.get_matched_types(type_name_template)])
    return result


def _try_find_matched_natvis_visualizer_for_base(value_type: lldb.SBType) -> Optional[AbstractVisDescriptor]:
    for index in range(value_type.GetNumberOfDirectBaseClasses()):
        base_type = value_type.GetDirectBaseClassAtIndex(index).GetType()
        base_type_name = base_type.GetName()
        try:
            base_type_name_template = parse_type_name_template(base_type_name)
        except Exception as e:
            log('Parsing typename {} failed: {}', base_type_name, e)
            raise

        viz_candidates = _get_matched_type_visualizers(base_type_name_template, True)
        if viz_candidates:
            return NatVisDescriptor(viz_candidates, base_type_name_template)

        deep_base = _try_find_matched_natvis_visualizer_for_base(base_type)
        if deep_base is not None:
            return deep_base

    return None


def _try_get_matched_visualizers(value_type: lldb.SBType, natvis_enabled) -> Optional[AbstractVisDescriptor]:
    value_type: lldb.SBType = value_type.GetUnqualifiedType()
    value_type_name = value_type.GetName()

    if natvis_enabled:
        log("Trying to find natvis visualizer for type: '{}'...", value_type_name)
        try:
            type_name_template = parse_type_name_template(value_type_name)
        except Exception as e:
            log('Parsing typename {} failed: {}', value_type_name, e)
            raise
        viz_candidates = _get_matched_type_visualizers(type_name_template)
        if viz_candidates:
            log("Found natvis visualizer for type: '{}'", value_type_name)
            return NatVisDescriptor(viz_candidates, type_name_template)

    return _try_get_matched_builtin_visualizer(value_type, natvis_enabled)


def _try_get_matched_builtin_visualizer(value_type, natvis_enabled):
    value_type_name = value_type.GetName()
    log("Trying to find builtin visualizer for type: '{}'", value_type_name)

    type_class = value_type.GetTypeClass()
    if type_class == lldb.eTypeClassTypedef:
        value_typedef_type = value_type.GetTypedefedType()
        value_typedef_type_name = value_typedef_type.GetName()
        log("Type '{}' is typedef to type '{}'", value_type_name, value_typedef_type_name)
        if value_typedef_type_name != value_type_name:
            return _try_get_matched_visualizers(value_typedef_type, natvis_enabled)

    if type_class == lldb.eTypeClassBuiltin:
        char_presentation_info = CharVisDescriptor.char_types.get(value_type_name)
        if char_presentation_info is not None:
            return CharVisDescriptor(char_presentation_info)
        if value_type_name in NumberVisDescriptor.numeric_types:
            return NumberVisDescriptor(value_type_name)

    if type_class == lldb.eTypeClassArray:
        array_element_type: SBType = value_type.GetArrayElementType()
        array_element_type_name = array_element_type.GetName()
        str_presentation_info = CharVisDescriptor.char_types.get(array_element_type_name)
        if str_presentation_info is not None:
            array_size = value_type.size // array_element_type.GetByteSize()
            return CharArrayOrPointerVisDescriptor(str_presentation_info, True, array_size)
        return GenericArrayVisDescriptor()

    if type_class == lldb.eTypeClassPointer:
        pointee_type: SBType = value_type.GetPointeeType()
        pointee_type_name = pointee_type.GetName()
        str_presentation_info = CharVisDescriptor.char_types.get(pointee_type_name)
        if str_presentation_info is not None:
            return CharArrayOrPointerVisDescriptor(str_presentation_info, False, None)
        # TODO: check pointer on typedef
        pointee_type_class = pointee_type.GetTypeClass()
        pointee_expands = pointee_type_class in {lldb.eTypeClassStruct,
                                                 lldb.eTypeClassClass,
                                                 lldb.eTypeClassUnion}
        # this is a hack
        # proper solution would be to clone stream inside visualiser and fallback if pointee summary is empty
        pointee_has_empty_description = pointee_type_name == 'void' or pointee_type_class == lldb.eTypeClassFunction
        return GenericPointerVisDescriptor(pointee_expands, pointee_has_empty_description)

    if type_class == lldb.eTypeClassReference:
        return GenericReferenceVisDescriptor()

    if type_class == lldb.eTypeClassStruct or type_class == lldb.eTypeClassClass or type_class == lldb.eTypeClassUnion:
        if natvis_enabled:
            natvis = _try_find_matched_natvis_visualizer_for_base(value_type)
            if natvis is not None:
                return natvis
        lambda_name = _try_extract_lambda_type_name(value_type_name)
        if lambda_name is not None:
            return LambdaVisDescriptor(value_type, lambda_name)
        return StructVisDescriptor(value_type)

    # No matched builtin vis descriptor found
    return None


def _try_extract_lambda_type_name(type_name: str) -> Optional[str]:
    idx = type_name.rfind('<lambda_')
    if idx == -1:
        return None
    if type_name[-1] != '>':
        return None
    if idx == 0:
        return type_name
    extracted_name = type_name[idx + len("<lambda_"):-1]
    if not extracted_name.isalnum():
        return None
    return type_name[idx:]
