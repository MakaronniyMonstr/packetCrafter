import tkinter as tk
from tkinter import ttk
from enum import Enum


class FrameState(Enum):
    DISABLED = 'disabled'
    NORMAL = 'normal'
    READONLY = 'readonly'
    SELECTED = 'selected'
    UNSELECTED = '!selected'


class HorizontalRadioButtonInput:
    def __init__(self, root: tk.Tk, radios: [str]):
        self.value = tk.IntVar()
        self.value.set(0)

        self.frame = tk.Frame(root)

        for (i, el) in enumerate(radios):
            r = tk.Radiobutton(self.frame, text=el, value=i, variable=self.value)
            r.pack(side=tk.LEFT)


class VerticalFlags(tk.Frame):
    def __init__(self, root, text, flags, result_handler):
        super().__init__(root)
        self.vars = []
        self.checks = []

        self.result = tk.IntVar(value=0)
        self.result.trace('w', lambda *args: result_handler(self.result.get()))

        lbl = tk.Label(self, text=text)
        lbl.pack(side=tk.TOP)

        for (i, el) in enumerate(flags):
            var = tk.BooleanVar()
            var.trace('w', lambda *args: self._compute_result(1, list(filter(lambda idx: self.vars[idx]._name in args[0], range(len(self.vars))))))
            self.vars.append(var)
            check = ttk.Checkbutton(self, variable=var, text=el, width=6)
            self.checks.append(check)
            check.pack(side=tk.TOP)

    def _compute_result(self, value, v):
        old_val = self.result.get()
        self.result.set(old_val ^ (value << v[0]))

    def set(self, value: int):
        return

    def disable(self):
        for el in self.checks:
            el['state'] = FrameState.DISABLED.value

    def enable(self):
        for el in self.checks:
            el['state'] = FrameState.NORMAL.value


class LabeledEntry(tk.Frame):

    """
    @:param root Root frame
    @:param label Label text
    @:param entry_handler On data changed function. lambda value: f(value)
    """
    def __init__(self, root, label, entry_handler, lbl_width=7, entry_width=9):
        super().__init__(root)

        lbl = tk.Label(self,
                       text=label,
                       width=lbl_width,
                       anchor=tk.E)
        lbl.pack(side=tk.LEFT)

        self.field = tk.StringVar()
        self.entry = tk.Entry(self,
                              width=entry_width,
                              textvariable=self.field)
        self.entry.pack(side=tk.LEFT)

        self.entry_handler = entry_handler
        self.callback = self.field.trace_add(['write'], lambda *args: self.entry_handler(self.field.get()))

    def set(self, value):
        self.field.trace_remove(['write'], self.callback)
        self.field.set(value)
        self.callback = self.field.trace_add(['write'], lambda *args: self.entry_handler(self.field.get()))

    def get(self):
        return self.field.get()

    def enable(self):
        self.entry['state'] = FrameState.NORMAL.value

    def disable(self):
        self.entry['state'] = FrameState.DISABLED.value


class LabeledCombobox(tk.Frame):
    def __init__(self, root, label, values, combobox_handler, lbl_width=7, box_width=9):
        super().__init__(root)

        lbl = tk.Label(self, text=label, width=lbl_width)
        lbl.pack(side=tk.LEFT)

        self.field = tk.StringVar(value=values[0])
        self.field.trace('w', lambda *args: combobox_handler(self.field.get()))
        self.box = ttk.Combobox(self,
                                width=box_width,
                                values=values,
                                textvariable=self.field,
                                state=FrameState.READONLY.value)
        self.box.pack(side=tk.LEFT)

    def disable(self):
        self.box['state'] = FrameState.DISABLED.value

    def enable(self):
        self.box['state'] = FrameState.READONLY.value

    def get(self):
        return self.field.get()




