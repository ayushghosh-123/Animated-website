from __future__ import annotations

import threading
from threading import Thread
from typing import Callable

import lldb
from renderers.jb_lldb_logging import log


class DebuggerEventsHandler:

    def __init__(self, debugger: lldb.SBDebugger):
        self._id: int = id(self)
        self._debugger: lldb.SBDebugger = debugger
        self._listener: lldb.SBListener = debugger.GetListener()

        self._initialize()

        self._stop: bool = False

        self._target_handlers = list[Callable]()

        self._thread: Thread = Thread(target=self._event_loop)
        log("{}({}): Starting event loop thread", __class__.__name__, self._id)
        self._thread.start()

    def add_target_handler(self, handler: Callable):
        log("{}({}): Adding SBTarget handler", __class__.__name__, self._id)
        self._target_handlers.append(handler)

    def stop(self):
        self._stop = True
        log("{}({}): Stop requested", __class__.__name__, self._id)

    def __del__(self):
        log("{}({}): Destructor", __class__.__name__, self._id)
        self._stop = True

        if self._thread.ident != threading.current_thread().ident:
            self._thread.join(30)
            assert not self._thread.is_alive()

    def _initialize(self):
        if not self._listener.IsValid():
            raise "Invalid listener"

        self._listener.StartListeningForEventClass(self._debugger,
                                                   lldb.SBTarget.GetBroadcasterClassName(),
                                                   lldb.SBTarget.eBroadcastBitModulesLoaded | lldb.SBTarget.eBroadcastBitModulesUnloaded
                                                   )

    def handle_target_event(self, event: lldb.SBEvent):
        assert isinstance(event, lldb.SBEvent)

        log("{}({}): handle_target_event, event_type: {}", __class__.__name__, self._id, event.GetType())

        for handler in self._target_handlers:
            handler()

    def _event_loop(self):
        event = lldb.SBEvent()
        log("{}({}): Entering event loop", __class__.__name__, self._id)

        try:

            while not self._stop:
                got_event = self._listener.WaitForEvent(1, event)
                if not got_event:
                    continue

                if not event.IsValid():
                    log("{}({}): Got event but it's invalid", __class__.__name__, self._id)
                    continue
                elif not event.GetBroadcaster().IsValid():
                    log("{}({}): Got event but it's broadcaster invalid", __class__.__name__, self._id)
                    continue

                if lldb.SBTarget.EventIsTargetEvent(event):
                    self.handle_target_event(event)
        except Exception as e:
            log("{}: Exception in event loop, error: {}", __class__.__name__, str(e))
            raise
        finally:
            log("{}({}): Exiting from event loop", __class__.__name__, self._id)
