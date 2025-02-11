from .jb_lldb_logging import log


# Associate source files and storage of parsed type visualizers.
# Every type viz storage also contains list of registered summaries and synthetics.
class FormattersManager(object):
    class FormatterEntry(object):
        def __init__(self, storage, loader):
            self.storage = storage
            self.loader = loader

    def __init__(self, summary_func_name, synthetic_provider_class_name):
        self.formatter_entries = {}
        self.summary_func_name = summary_func_name
        self.synthetic_provider_class_name = synthetic_provider_class_name

    def get_all_registered_files(self):
        return self.formatter_entries.keys()

    def get_all_type_viz(self):
        return [e.storage for e in self.formatter_entries.values()]

    def register(self, filepath, loader):
        log("Registering types storage for '{}'...", filepath)
        storage = loader(filepath)
        self.formatter_entries[filepath] = self.FormatterEntry(storage, loader)

    def unregister(self, filepath):
        log("Unregistering types storage for '{}'...", filepath)
        try:
            del self.formatter_entries[filepath]
        except KeyError:
            log("Key '{}' wasn't found in formatters storage...", filepath)
            return

    def reload(self, filepath):
        try:
            entry = self.formatter_entries[filepath]
        except KeyError:
            log("Key '{}' wasn't found in formatters storage...", filepath)
            return

        entry.storage = entry.loader(filepath)
