from gui.views import *

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
