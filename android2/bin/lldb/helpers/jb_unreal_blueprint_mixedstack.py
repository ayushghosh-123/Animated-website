import abc
import struct
import time

from datetime import datetime
from typing import Optional

import lldb
import renderers.jb_lldb_logging as logging


class LLDBCommand(abc.ABC):
    """
    See `CommandObjectType` <https://lldb.llvm.org/use/python-reference.html>.
    """

    command: str

    @abc.abstractmethod
    def __init__(self, _: lldb.SBDebugger, __: dict):
        pass

    @classmethod
    def register_lldb_command(cls, debugger: lldb.SBDebugger, module_name: str) -> None:
        command = f"command script add --class {module_name}.{cls.__name__} {cls.command}"
        debugger.HandleCommand(command)

    @abc.abstractmethod
    def __call__(self, debugger: lldb.SBDebugger, command: str,
                 execution_context: lldb.SBExecutionContext,
                 command_return: lldb.SBCommandReturnObject) -> None:
        pass

    @staticmethod
    def _log(fmt: str, *args, **kwargs) -> None:
        logging.log(f"{__name__}> " + fmt, *args, **kwargs)


class JBIsUnrealAvailable(LLDBCommand):
    command: str = 'jb_unreal_blueprint_get_unreal_version'

    def __init__(self, debugger: lldb.SBDebugger, bindings: dict):
        self._decl_suffix: str = f'_{datetime.now().strftime("%Y%m%d%H%M%S")}'
        self._is_memory_allocated = False
        super().__init__(debugger, bindings)

    def __call__(self, debugger: lldb.SBDebugger, args: str,
                 execution_context: lldb.SBExecutionContext,
                 command_return: lldb.SBCommandReturnObject) -> None:
        self.get_unreal_version(debugger, args, command_return, execution_context)

    def get_unreal_version(self, debugger: lldb.SBDebugger, _: str, command_return: lldb.SBCommandReturnObject, ___) -> None:
        self._log('Getting Unreal version')
        target: lldb.SBTarget = debugger.GetSelectedTarget()
        assert target, "No target selected"

        version = _get_unreal_version(target)

        if version is None:
            self._log('Unreal module not found')
            command_return.SetStatus(lldb.eReturnStatusFailed)
            command_return.SetError('Unreal module not found')
            return

        self._log(f'Unreal version: {version}')

        command_return.SetStatus(lldb.eReturnStatusSuccessFinishResult)
        command_return.AppendMessage(str(version))


class JBGetBlueprintStackCommand(LLDBCommand):
    command: str = 'jb_unreal_blueprint_get_stack'

    PROTO_ERROR_BP_FRAMES = "ERROR_BP_FRAMES"
    PROTO_ERROR_AV_EXCEPTION = "ERROR_AV_EXCEPTION"
    PROTO_NONE_BP_FRAMES = "NONE_BP_FRAMES"
    PROTO_DEBUGGER_PLUGIN_MISSING = "DEBUGGER_PLUGIN_MISSING"

    MAX_STRING_LENGTH = 1024
    RESULT_CODE_SIZE_IN_BYTES = 4
    STRING_BUFFER_SIZE_IN_BYTES = RESULT_CODE_SIZE_IN_BYTES + MAX_STRING_LENGTH * 2
    BUFFER_SIZE_IN_BYTES = RESULT_CODE_SIZE_IN_BYTES + STRING_BUFFER_SIZE_IN_BYTES * 3

    def __init__(self, debugger: lldb.SBDebugger, bindings: dict):
        super().__init__(debugger, bindings)

        self.cached_objects: dict[str, str] = {}

    def __call__(self, debugger: lldb.SBDebugger, args: str,
                 execution_context: lldb.SBExecutionContext,
                 command_return: lldb.SBCommandReturnObject) -> None:
        self._log('Getting Blueprint stack data, command: "{}", args: "{}"', self.command, args)
        start_time = time.process_time_ns()

        try:
            is_success = self.get_stack_data(debugger, args, command_return, execution_context)
        finally:
            end_time = time.process_time_ns()

        if is_success:
            self._log(f'Getting Blueprint stack data took {(end_time - start_time) / 1000000}ms.')
        else:
            self._log(f'Got error while getting stack data. Elapsed time: {(end_time - start_time) / 1000000}ms.')

    def get_stack_data(self, debugger: lldb.SBDebugger, args: str, command_return: lldb.SBCommandReturnObject, ___) -> bool:

        try:

            thread_id = int(args)

            target: lldb.SBTarget = debugger.GetSelectedTarget()
            assert target, "No target selected"

            process: lldb.SBProcess = target.GetProcess()
            thread: lldb.SBThread = process.GetThreadByID(thread_id)

            rider_plugin_module = _get_rider_debug_supporting_module(target)

            if not rider_plugin_module:
                self._log('Rider debugger plugin is not available')
                command_return.SetStatus(lldb.eReturnStatusFailed)
                command_return.SetError('Rider debugger plugin is not available')
                command_return.AppendMessage(self.PROTO_DEBUGGER_PLUGIN_MISSING)
                return False

            data_string = self.get_bp_from_stack(process, rider_plugin_module, thread)

            message = self.PROTO_NONE_BP_FRAMES
            command_status = lldb.eReturnStatusSuccessFinishNoResult
            if len(data_string) == 0:
                self._log(f'Stack does not contains data Blueprint data')
            else:
                self._log(f'Stack data was successfully collected, data: {data_string}')
                message = data_string
                command_status = lldb.eReturnStatusSuccessFinishResult

            command_return.SetStatus(command_status)
            command_return.AppendMessage(message)

            return True

        except Exception as e:
            error_message = str(e)
            return_message = self.PROTO_ERROR_BP_FRAMES

            self._log(f'Can\'t get stack data: {error_message}')
            command_return.SetStatus(lldb.eReturnStatusFailed)
            command_return.SetError(f"Can't get blueprint stack: {error_message}")
            if "Execution was interrupted, reason: Exception 0xc0000005 encountered at address" in error_message:
                return_message = self.PROTO_ERROR_AV_EXCEPTION

            command_return.AppendMessage(return_message)
            return False

    def get_bp_from_stack(self, process: lldb.SBProcess, rider_plugin_module: str, thread: lldb.SBThread) -> str:
        options = _get_expression_options()
        data_string = ""
        previous_data_string_in_stack = ""
        prev_function_name: Optional[str] = None
        for i, frame in enumerate(thread):

            frame: lldb.SBFrame = frame

            function_name: str = (frame.GetFunctionName() or '').replace(' ', '')
            tmp_prev_function_name = prev_function_name
            prev_function_name = function_name

            possible_duplicate = False

            match (function_name, tmp_prev_function_name):
                case ('ProcessLocalScriptFunction(UObject*,FFrame&,void*const)', _):
                    object_param_name = 'Context'
                case ('UObject::ProcessEvent(UFunction*,void*)', 'UFunction::Invoke(UObject*,FFrame&,void*const)'):
                    object_param_name = 'this'
                    possible_duplicate = True
                case _:
                    continue

            assert object_param_name is not None

            context: lldb.SBValue = frame.FindVariable(object_param_name)
            _validate_value(context, f"Can't find {object_param_name} in frame")
            function: lldb.SBValue = frame.FindVariable('Function')
            _validate_value(function, "Can't find Function in frame")

            cache_key = f'{context.GetAddress().file_addr}_{function.GetAddress().file_addr}'

            if cache_key not in self.cached_objects:
                data_frame_str = self.get_data_from_bp_stack_frame(frame, object_param_name, options, process, rider_plugin_module)
                self.cached_objects[cache_key] = data_frame_str

            if possible_duplicate:
                if previous_data_string_in_stack == self.cached_objects[cache_key]:
                    previous_data_string_in_stack = ""
                    continue
            previous_data_string_in_stack = self.cached_objects.get(cache_key, "")

            data_string += "" if len(data_string) == 0 else "<<<!!!"
            data_string += f"{frame.idx}^^^{self.cached_objects[cache_key]}"

        return data_string

    def get_data_from_bp_stack_frame(self, frame: lldb.SBFrame, object_param_name: str,
                                     options: lldb.SBExpressionOptions,
                                     process: lldb.SBProcess, rider_plugin_module: str) -> str:
        value: lldb.SBValue = frame.EvaluateExpression(f"""
                        #pragma x__jb__context_operator(module, "{rider_plugin_module}")
                        RiderDebuggerSupportBlueprintFunctionCallContext.Context = {object_param_name};
                        #pragma x__jb__context_operator(module, "{rider_plugin_module}")
                        RiderDebuggerSupportBlueprintFunctionCallContext.Function = Function;
                        #pragma x__jb__context_operator(module, "{rider_plugin_module}")
                        & RiderDebuggerSupportBlueprintFunctionCallContext
                        """, options)

        _validate_value(value, "Can't create call context")

        new_value: lldb.SBValue = value.Dereference()

        _validate_value(new_value, "Can't dereference call context")

        result = new_value.EvaluateExpression(f"""
                        #pragma x__jb__context_operator(module, "{rider_plugin_module}")
                        RiderDebuggerSupport_GetBlueprintFunction(Function, Context);
                        #pragma x__jb__context_operator(module, "{rider_plugin_module}")
                        & RiderDebuggerSupportBlueprintFunctionBuffer
                        """, options)

        if not result.IsValid() or not result.GetError().Success():
            raise RuntimeError(f"Can't call RiderDebuggerSupport_GetBlueprintFunction: {result.GetError()}")

        data_address = result.GetValueAsUnsigned()
        mem_error: lldb.SBError = lldb.SBError()
        dumped_data = process.ReadMemory(data_address, self.BUFFER_SIZE_IN_BYTES, mem_error)
        if not mem_error.Success():
            raise RuntimeError(f"Can't read memory: {mem_error}")

        new_bytes = bytearray(dumped_data)

        result_code, offset_str1 = _read_int_from_bytes(0, new_bytes)
        str1 = _read_utf16_string_from_bytes(offset_str1, new_bytes)
        str2 = _read_utf16_string_from_bytes(offset_str1 + self.STRING_BUFFER_SIZE_IN_BYTES, new_bytes)
        str3 = _read_utf16_string_from_bytes(offset_str1 + 2 * self.STRING_BUFFER_SIZE_IN_BYTES, new_bytes)
        data_frame_str = f"{str1}^^^{str2}^^^{str3}"
        return data_frame_str


def _read_utf16_string_from_bytes(offset: int, data: bytearray) -> [str]:
    length_in_chars = struct.unpack_from('I', data, offset)[0]
    offset += 4
    # Unreal string always uses utf-16
    # see https://docs.unrealengine.com/5.3/en-US/character-encoding-in-unreal-engine/#ueinternalstringrepresentation
    # that's why we use wchar_t in C++ code (RiderDebuggerSupport) and utf-16 here
    return data[offset:offset + length_in_chars * 2].decode('utf-16')


def _read_int_from_bytes(offset: int, data: bytearray) -> [int, int]:
    res = struct.unpack_from('I', data, offset)[0]
    offset += 4
    return res, offset


def _get_expression_options():
    expression_options = lldb.SBExpressionOptions()
    expression_options.SetSuppressPersistentResult(True)
    return expression_options


def _validate_value(value: lldb.SBValue, message: str) -> None:
    if not value.IsValid() or not value.GetError().Success():
        raise RuntimeError(f"{message}: {value.GetError()}")


RIDER_DEBUG_SUPPORT_AVAILABLE_CONST = "RiderDebuggerSupport".casefold()


def _get_rider_debug_supporting_module(target: lldb.SBTarget) -> Optional[str]:
    modules: list[lldb.SBModule] = target.modules

    for module in modules:
        if RIDER_DEBUG_SUPPORT_AVAILABLE_CONST in module.file.basename.casefold():
            return module.file.basename
    else:
        return None


def _get_unreal_version(target: lldb.SBTarget) -> Optional[int]:
    modules: list[lldb.SBModule] = target.modules

    ue4_core_module = "UE4Editor-CoreUObject.dll"
    ue5_core_module = "UnrealEditor-CoreUObject.dll"

    for module in modules:

        if module.file.basename == ue4_core_module:
            return 4
        if module.file.basename == ue5_core_module:
            return 5
    else:
        return None


def __lldb_init_module(debugger: lldb.SBDebugger, _):
    JBIsUnrealAvailable.register_lldb_command(debugger, __name__)
    JBGetBlueprintStackCommand.register_lldb_command(debugger, __name__)
