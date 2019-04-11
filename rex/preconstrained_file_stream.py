
from angr.state_plugins.plugin import SimStatePlugin
from angr.storage.file import SimFileStream


class SimPreconstrainedFileStream(SimFileStream):
    def __init__(self, name, preconstraining_handler=None, **kwargs):
        super().__init__(name, **kwargs)

        self.preconstraining_handler = preconstraining_handler
        self._attempted_preconstraining = False

    def read(self, pos, size, **kwargs):

        if not self._attempted_preconstraining:
            self._attempted_preconstraining = True
            self.preconstraining_handler(self)

        return super().read(pos, size, **kwargs)

    @SimStatePlugin.memo
    def copy(self, memo):
        copied = super().copy(memo)
        copied.preconstraining_handler = self.preconstraining_handler
        copied._attempted_preconstraining = self._attempted_preconstraining
        return copied
