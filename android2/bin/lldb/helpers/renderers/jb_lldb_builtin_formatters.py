import lldb
from lldb import *
from renderers.jb_lldb_format_specs import *
from renderers.jb_lldb_utils import *
from renderers.jb_lldb_string_utils import *
from renderers.jb_lldb_declarative_formatters_options import *
from renderers.jb_lldb_format import update_value_dynamic_state


class StructChildrenProvider(AbstractChildrenProvider):
    def __init__(self, value_non_synth: lldb.SBValue):
        self.value = value_non_synth
        self.format_spec = value_non_synth.GetFormat()

    def num_children(self) -> int:
        return self.value.GetNumChildren()

    def get_child_index(self, name) -> int:
        return self.value.GetIndexOfChildWithName(name)

    def get_child_at_index(self, index):
        child = self.value.GetChildAtIndex(index)
        # non_synth children haven't any formatting
        # so apply parent value formatting without non-inheritable flags
        child_root = get_root_value(child)
        child_root.SetFormat(self.format_spec & eFormatInheritedFlagsMask)

        update_value_dynamic_state(child)

        return child


class WrappedChildrenProvider(AbstractChildrenProvider):
    def __init__(self, value: lldb.SBValue):
        self.value = value

    def num_children(self) -> int:
        return self.value.GetNumChildren()

    def get_child_index(self, name) -> int:
        return self.value.GetIndexOfChildWithName(name)

    def get_child_at_index(self, index):
        child = self.value.GetChildAtIndex(index)
        update_value_dynamic_state(child)
        return child


class PointerChildrenProvider(AbstractChildrenProvider):
    def __init__(self, value_non_synth: lldb.SBValue):
        # no need to manipulate formats here
        # pointees inherit all formatting from pointer parents (?)
        self.pointee = value_non_synth.Dereference()

    def num_children(self) -> int:
        if not self.pointee.IsValid():
            return 0
        return 1

    def get_child_index(self, name) -> int:
        return INVALID_CHILD_INDEX

    def get_child_at_index(self, index):
        return self.pointee


class NumberVisDescriptor(AbstractVisDescriptor):
    numeric_types = {"bool", "short", "unsigned short", "int", "unsigned int", "unsigned", "long", "unsigned long",
                     "long long", "unsigned long long", "__int128", "unsigned __int128", "half", "float", "double",
                     "long double"}
    integer_types = {"short": (2, True), "unsigned short": (2, False),
                     "int": (4, True), "unsigned int": (4, False), "unsigned": (4, False),
                     "long": (4, True), "unsigned long": (4, False),
                     "long long": (8, True), "unsigned long long": (8, False),
                     "__int128": (16, True), "unsigned __int128": (16, False),
                     }
    float_types = {"half", "float", "double", "long double"}
    formats = {eFormatHex, eFormatHexNoPrefix, eFormatHexUppercase, eFormatHexUppercaseNoPrefix,
               eFormatOctal, eFormatBinary, eFormatBinaryNoPrefix, eFormatDecimal, eFormatChar}
    eFormatHexShowBoth = eFormatBasicSpecsMask + 1

    def __init__(self, char_type_name: str):
        self.value_type_name = char_type_name
        self.presenters = {}
        self.default_presenter = lambda x, s: NumberVisDescriptor.output_integer(x, s)

        if self.value_type_name == "bool":
            self.default_presenter = lambda x, s: s.output_keyword("true" if x.GetValueAsUnsigned() != 0 else "false")

        elif self.value_type_name in self.integer_types:
            size, signed = self.integer_types[self.value_type_name]
            format_hex = "0x{{:0{}x}}".format(size * 2)
            format_no_prefix = "{{:0{}x}}".format(size * 2)
            format_hex_uppercase = "0x{{:0{}X}}".format(size * 2)
            format_hex_uppercase_no_prefix = "{{:0{}X}}".format(size * 2)
            format_octal = "{{:0{}o}}".format(size * 3)
            format_binary = "0b{{:0{}b}}".format(size * 8)
            format_binary_no_prefix = "{{:0{}b}}".format(size * 8)

            def output_number_with_hex(x, s: Stream):
                NumberVisDescriptor.output_integer(x, s)
                s.output(" [")
                s.output_number(format_hex.format(x.GetValueAsUnsigned()))
                s.output("]")

            self.presenters = {
                eFormatHex: lambda x, s: s.output_number(format_hex.format(x.GetValueAsUnsigned())),
                eFormatHexNoPrefix: lambda x, s: s.output_number(format_no_prefix.format(x.GetValueAsUnsigned())),
                eFormatHexUppercase: lambda x, s: s.output_number(format_hex_uppercase.format(x.GetValueAsUnsigned())),
                eFormatHexUppercaseNoPrefix: lambda x, s: s.output_number(
                    format_hex_uppercase_no_prefix.format(x.GetValueAsUnsigned())),
                eFormatOctal: lambda x, s: s.output_number(format_octal.format(x.GetValueAsUnsigned())),
                eFormatBinary: lambda x, s: s.output_number(format_binary.format(x.GetValueAsUnsigned())),
                eFormatBinaryNoPrefix: lambda x, s: s.output_number(
                    format_binary_no_prefix.format(x.GetValueAsUnsigned())),
                eFormatDecimal: lambda x, s: NumberVisDescriptor.output_decimal(x, signed, s),
                eFormatChar: lambda x, s: NumberVisDescriptor.output_char(x.GetValueAsUnsigned(), s),
                self.eFormatHexShowBoth: output_number_with_hex,
            }
        elif self.value_type_name in self.float_types:
            self.default_presenter = lambda x, s: NumberVisDescriptor.output_float(x, s)

    @staticmethod
    def output_char(code: int, stream: Stream):
        # char format specifier interprets integers as shorts in utf-16 encoding
        code = code & 0xffff
        enc = 'utf-16'
        stream.output_number(str(code))
        stream.output(" ")
        stream.output_string("'" + escape_char(code, 2, enc) + "'")

    @staticmethod
    def output_integer(value_non_synth: lldb.SBValue, stream: Stream):
        # no need to get static value for numeric values
        value_non_synth.SetFormat(eFormatDefault)
        stream.output_number(value_non_synth.GetValue())

    @staticmethod
    def output_decimal(value_non_synth: lldb.SBValue, signed: bool, stream: Stream):
        fmt = signed and eFormatDecimal or eFormatUnsigned
        # no need to get static value for numeric values
        value_non_synth.SetFormat(fmt)
        stream.output_number(value_non_synth.GetValue())

    @staticmethod
    def output_float(value_non_synth: lldb.SBValue, stream: Stream):
        # no need to get static value for numeric values
        value_non_synth.SetFormat(eFormatFloat)
        stream.output_number(value_non_synth.GetValue())

    def output_summary(self, value_non_synth: lldb.SBValue, stream: Stream):
        if not value_non_synth.IsValid():
            stream.output('???')
            return
        err: SBError = value_non_synth.GetError()
        if err is not None and err.Fail():
            stream.output('???')
            return

        spec = value_non_synth.GetFormat() & eFormatBasicSpecsMask
        # check for global hex option if format specifier was not explicitly set
        if is_global_hex() and spec not in self.formats:
            spec = eFormatHex
            if is_global_hex_show_both():
                spec = self.eFormatHexShowBoth
        presenter = self.presenters.get(spec, self.default_presenter)
        presenter(value_non_synth, stream)


CharPresentationInfo = Tuple[int, str, str]


class CharVisDescriptor(AbstractVisDescriptor):
    char_types = {"char": (1, "", '__locale__'),
                  "unsigned char": (1, "", '__locale__'),
                  "signed char": (1, "", '__locale__'),
                  "wchar_t": (2, "L", 'utf-16'),
                  "char8_t": (1, "", 'utf-8'),
                  "char16_t": (2, "u", 'utf-16'),
                  "char32_t": (4, "U", 'utf-32')}

    def __init__(self, char_presentation_info: CharPresentationInfo):
        self.char_presentation_info = char_presentation_info

    def output_summary(self, value_non_synth: lldb.SBValue, stream: Stream):
        char_size, prefix, enc = self.char_presentation_info
        if enc == '__locale__':
            enc = get_locale()
        err = SBError()
        code = value_non_synth.GetValueAsSigned(err)
        if err.Fail():
            stream.output('<error>')
            return
        ordinal = code
        if code < 0:
            # convert signed to unsigned
            if code >= -0x80:
                ordinal = code & 0xff
            elif code >= -0x8000:
                ordinal = code & 0xffff
            elif code >= -0x80000000:
                ordinal = code & 0xffffffff
        if is_global_hex():
            if is_global_hex_show_both():
                stream.output_number(str(code))
                stream.output_number(" [{0:#x}]".format(ordinal))
            else:
                stream.output_number("{0:#x}".format(ordinal))
        else:
            stream.output_number(str(code))
        stream.output(" ")
        # Unlike Visual Studio's behavior we present wchar_t as L'x' (for consistency with wide strings L"xxx")
        stream.output_string(prefix + "'" + escape_char(ordinal, char_size, enc) + "'")


def _cast_value_to_array(value_non_synth: lldb.SBValue, is_array: bool, fmt: int, array_size: int):
    val_type = value_non_synth.GetType()
    if is_array:
        elem_type = val_type.GetArrayElementType()
        value_non_synth = value_non_synth.AddressOf()
    else:
        elem_type = val_type.GetPointeeType()

    upd_val_type = elem_type.GetArrayType(array_size).GetPointerType()
    new_val = value_non_synth.Cast(upd_val_type).Dereference()

    # reset format as array flag
    new_val_fmt = fmt & ~eFormatAsArray
    set_value_format(new_val, new_val_fmt)
    return new_val


class CharArrayOrPointerVisDescriptor(AbstractVisDescriptor):
    def __init__(self, presentation_info: CharPresentationInfo, is_array: bool, array_size=None, formatted_array=False):
        self.presentation_info = presentation_info
        self.is_array = is_array
        self.array_size = array_size
        self.formatted_array = formatted_array

    def output_summary(self, value_non_synth: lldb.SBValue, stream: Stream):
        char_size, prefix, enc = self.presentation_info
        fmt = value_non_synth.GetFormat()

        if fmt & eFormatAsArray != 0:
            provider, new_val = self._format_as_array(value_non_synth, fmt)
            return provider.output_summary(new_val.GetNonSyntheticValue(), stream)

        basic_fmt = fmt & eFormatBasicSpecsMask
        suppress_address = (fmt & eFormatNoAddress != 0) or (basic_fmt in FMT_STRING_SET_ALL)
        if self.is_array:
            address = value_non_synth.GetLoadAddress()
        else:
            address = value_non_synth.GetValueAsUnsigned()

        if not suppress_address:
            stream.output_address(address)
            stream.output(" ")

        zero_required = not self.formatted_array

        err = lldb.SBError()
        max_size = self.array_size * char_size if self.array_size is not None else None
        content, zero_found = extract_string(value_non_synth.GetProcess(), address, char_size, max_size, err)
        if err.Fail():
            stream.output('<error>')
            return

        if enc == '__locale__':
            enc = get_locale()
        s = escape_bytes(content, enc)

        quote = basic_fmt not in FMT_STRING_NOQUOTES_SET
        result = StringIO()

        if quote:
            result.write(prefix)
            result.write('"')
        result.write(s)
        if zero_found or not zero_required:
            if quote:
                result.write('"')
        else:
            result.write('...')
        stream.output_string(result.getvalue())

    def prepare_children(self, value_non_synth: lldb.SBValue):
        fmt = value_non_synth.GetFormat()

        if fmt & eFormatAsArray != 0:
            provider, new_val = self._format_as_array(value_non_synth, fmt)
            return provider.prepare_children(new_val.GetNonSyntheticValue())

        return StructChildrenProvider(value_non_synth)

    def _format_as_array(self, value_non_synth: lldb.SBValue, fmt: int) -> Tuple[AbstractVisDescriptor, lldb.SBValue]:
        fmt_array_size = value_non_synth.GetFormatAsArraySize()
        # TODO: check fmt_array_size

        provider = CharArrayOrPointerVisDescriptor(self.presentation_info, True, fmt_array_size, True)
        new_val = _cast_value_to_array(value_non_synth, self.is_array, fmt, fmt_array_size)
        return provider, new_val


class GenericArrayVisDescriptor(AbstractVisDescriptor):
    def output_summary(self, value_non_synth: lldb.SBValue, stream: Stream):
        fmt = value_non_synth.GetFormat()
        if fmt & eFormatAsArray != 0:
            provider, new_val = self._format_as_array(value_non_synth, fmt)
            return provider.output_summary(new_val.GetNonSyntheticValue(), stream)

        basic_fmt = fmt & eFormatBasicSpecsMask
        str_presentation_info = FMT_STRING_SET_ALL.get(basic_fmt)
        if str_presentation_info is not None:
            provider = CharArrayOrPointerVisDescriptor(str_presentation_info, True, None)
            return provider.output_summary(value_non_synth, stream)

        address = value_non_synth.GetLoadAddress()
        stream.output_address(address)
        stream.output(" {")

        if stream.level >= g_max_recursion_level:
            stream.output('...')
        else:
            for child_index in range(value_non_synth.GetNumChildren()):
                if child_index != 0:
                    stream.output(", ")
                if stream.length > get_max_string_length():
                    stream.output("...")
                    break

                child: lldb.SBValue = value_non_synth.GetChildAtIndex(child_index)
                update_value_dynamic_state(child)
                stream.output_object(child.GetNonSyntheticValue())

        stream.output("}")

    def prepare_children(self, value_non_synth: lldb.SBValue):
        fmt = value_non_synth.GetFormat()

        if fmt & eFormatAsArray != 0:
            provider, new_val = self._format_as_array(value_non_synth, fmt)
            return provider.prepare_children(new_val.GetNonSyntheticValue())

        return StructChildrenProvider(value_non_synth)

    @staticmethod
    def _format_as_array(value_non_synth: lldb.SBValue, fmt: int) -> Tuple[AbstractVisDescriptor, lldb.SBValue]:
        fmt_array_size = value_non_synth.GetFormatAsArraySize()
        # TODO: check fmt_array_size
        provider = GenericArrayVisDescriptor()
        new_val = _cast_value_to_array(value_non_synth, True, fmt, fmt_array_size)
        return provider, new_val


RESOLVE_CONTEXT_MASK = lldb.eSymbolContextModule | lldb.eSymbolContextFunction | lldb.eSymbolContextSymbol

class GenericPointerVisDescriptor(AbstractVisDescriptor):
    def __init__(self, pointee_expands: bool, pointee_has_empty_description: bool):
        self.pointee_expands = pointee_expands
        self.pointee_has_empty_description = pointee_has_empty_description

    def output_summary(self, value_non_synth: lldb.SBValue, stream: Stream):
        fmt = value_non_synth.GetFormat()
        if fmt & eFormatAsArray != 0:
            provider, new_val = self._format_as_array(value_non_synth, fmt)
            return provider.output_summary(new_val.GetNonSyntheticValue(), stream)

        basic_fmt = fmt & eFormatBasicSpecsMask
        str_presentation_info = FMT_STRING_SET_ALL.get(basic_fmt)
        if str_presentation_info is not None:
            provider = CharArrayOrPointerVisDescriptor(str_presentation_info, False, None)
            return provider.output_summary(value_non_synth, stream)

        err = SBError()
        address = value_non_synth.GetValueAsUnsigned(err)
        if err.Fail():
            stream.output('???')
            return

        need_separator = False
        if value_non_synth.GetFormat() & eFormatNoAddress == 0:
            stream.output_address(address)
            need_separator = True

        sb_addr = SBAddress(address, value_non_synth.GetTarget())
        symbol_context: lldb.SBSymbolContext = sb_addr.GetSymbolContext(RESOLVE_CONTEXT_MASK)
        if symbol_context is not None:
            module: lldb.SBModule = symbol_context.GetModule()

            function: lldb.SBFunction = symbol_context.GetFunction()
            symbol: lldb.SBSymbol = symbol_context.GetSymbol()
            name = None
            if function is not None and function.IsValid():
                name = function.GetDisplayName() or function.GetName()
            elif symbol is not None and symbol.IsValid():
                name = symbol.GetDisplayName() or symbol.GetName()

            if name is not None:
                if need_separator:
                    stream.output(" ")
                stream.output("{")

                if module is not None and module.IsValid():
                    file: lldb.SBFileSpec = module.GetFileSpec()
                    file_name = file.GetFilename()
                    stream.output(file_name)
                    stream.output("!")

                stream.output(name)
                stream.output("}")

                need_separator = True

        if self.pointee_has_empty_description:
            return

        if need_separator:
            stream.output(" ")

        if stream.level >= g_max_recursion_level:
            stream.output('{...}')
        elif self.pointee_expands:
            stream.output_object(value_non_synth.Dereference().GetNonSyntheticValue())
        else:
            stream.output('{')
            if stream.length > get_max_string_length():
                stream.output("...")
            else:
                stream.output_object(value_non_synth.Dereference().GetNonSyntheticValue())
            stream.output('}')

    def prepare_children(self, value_non_synth: lldb.SBValue):
        fmt = value_non_synth.GetFormat()
        if fmt & eFormatAsArray != 0:
            provider, new_val = self._format_as_array(value_non_synth, fmt)
            return provider.prepare_children(new_val.GetNonSyntheticValue())

        err = SBError()
        address = value_non_synth.GetValueAsUnsigned(err)
        if err.Fail():
            return AbstractChildrenProvider()

        if self.pointee_expands:
            pointee = value_non_synth.Dereference()
            return WrappedChildrenProvider(pointee)
        return PointerChildrenProvider(value_non_synth)

    @staticmethod
    def _format_as_array(value_non_synth: lldb.SBValue, fmt: int) -> Tuple[AbstractVisDescriptor, lldb.SBValue]:
        fmt_array_size = value_non_synth.GetFormatAsArraySize()
        # TODO: check fmt_array_size

        provider = GenericArrayVisDescriptor()
        new_val = _cast_value_to_array(value_non_synth, False, fmt, fmt_array_size)
        return provider, new_val


class GenericReferenceVisDescriptor(AbstractVisDescriptor):
    def output_summary(self, value_non_synth: lldb.SBValue, stream: Stream):
        if stream.level >= g_max_recursion_level:
            stream.output('{...}')
        else:
            stream.output_object(value_non_synth.Dereference().GetNonSyntheticValue())

    def prepare_children(self, value_non_synth: lldb.SBValue):
        return WrappedChildrenProvider(value_non_synth.Dereference())


class StructVisDescriptor(AbstractVisDescriptor):
    def __init__(self, value_type: lldb.SBType):
        self.value_type = value_type

    def output_summary(self, value_non_synth: lldb.SBValue, stream: Stream):
        provider = self.prepare_children(value_non_synth)
        num_children = provider.num_children()

        # Skip base structs in summary presentation
        base_classes_count = self.value_type.GetNumberOfDirectBaseClasses()
        # TODO: what about virtual bases?
        # TODO: there is bug with empty bases that are not presented

        stream.output("{")
        if stream.level >= g_max_recursion_level or stream.length > get_max_string_length():
            stream.output('...')
        elif num_children == base_classes_count:
            stream.output('...')
        else:
            for child_index in range(base_classes_count, num_children):
                if child_index != base_classes_count:
                    stream.output(", ")

                if child_index > base_classes_count + 2 or stream.length > get_max_string_length():
                    stream.output("...")
                    break

                child: lldb.SBValue = provider.get_child_at_index(child_index)
                child_non_synth = child.GetNonSyntheticValue()
                child_name = child_non_synth.GetName() or ''
                stream.output(child_name)
                stream.output("=")
                if stream.length > get_max_string_length():
                    stream.output("...")
                    break

                stream.output_object(child_non_synth)

        stream.output("}")

    def prepare_children(self, value_non_synth: lldb.SBValue):
        if value_non_synth.MightHaveChildren():
            return StructChildrenProvider(value_non_synth)
        return super().prepare_children(value_non_synth)


class LambdaVisDescriptor(StructVisDescriptor):
    def __init__(self, value_type: lldb.SBType, lambda_name: str):
        super(LambdaVisDescriptor, self).__init__(value_type)
        self.lambda_name = lambda_name

    def output_summary(self, value_non_synth: lldb.SBValue, stream: Stream):
        value_type: SBType = value_non_synth.GetType()
        num = value_type.GetNumberOfMemberFunctions()
        for i in range(num):
            func: SBTypeMemberFunction = value_type.GetMemberFunctionAtIndex(i)
            func_name = func.GetName()
            if func_name != 'operator()':
                continue
            func_type: SBType = func.GetType()
            signature = func_type.GetName()
            if signature:
                stream.output('<lambda> ')
                stream.output(signature)
                stream.output(' ')

        super(LambdaVisDescriptor, self).output_summary(value_non_synth, stream)
