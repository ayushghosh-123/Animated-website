import lldb
import lldb.formatters

logger = lldb.formatters.Logger.Logger()
lldb.formatters.Logger._lldb_formatters_debug_level = 0

g_force_suppress_errors = False


def get_suppress_errors() -> bool:
    global g_force_suppress_errors
    return g_force_suppress_errors


def set_suppress_errors(val: bool):
    global g_force_suppress_errors
    g_force_suppress_errors = val


def set_logging_level(level):
    lldb.formatters.Logger._lldb_formatters_debug_level = level
    _reinit_logger()


def set_logging_file(file_name: str):
    lldb.formatters.Logger._lldb_formatters_debug_filename = file_name
    _reinit_logger()


def _reinit_logger():
    global logger
    logger = lldb.formatters.Logger.Logger()


def get_logging_level():
    # noinspection PyProtectedMember
    return lldb.formatters.Logger._lldb_formatters_debug_level


def log(fmt: str, *args, **kwargs):
    logger >> fmt.format(*args, **kwargs)


def get_logger() -> lldb.formatters.Logger.Logger:
    return logger
