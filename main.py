import tkinter as tk
from gui.components import *
from gui.views import *
import scapy.all
import scapy.layers.inet as layers

TITLE = '0.1a'


def main():
    window = tk.Tk()

    el = App(window)
    el.pack()

    window.title(TITLE)
    window.resizable(width=False, height=False)
    window.mainloop()


if __name__ == '__main__':
    main()
