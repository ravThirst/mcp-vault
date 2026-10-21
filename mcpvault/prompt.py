"""Small always-on-top unlock dialog. Prints the password to stdout; exit 1 on cancel."""

import sys
import tkinter as tk
from tkinter import ttk


def main(message: str = "") -> int:
    result = {"pw": None}
    root = tk.Tk()
    root.title("MCP Vault")
    root.resizable(False, False)
    root.attributes("-topmost", True)

    frame = ttk.Frame(root, padding=18)
    frame.grid()
    ttk.Label(frame, text="Unlock MCP Vault", font=("Segoe UI", 12, "bold")).grid(sticky="w")
    ttk.Label(frame, text="An MCP server is starting and needs its credentials.\nEnter your master password:",
              justify="left").grid(sticky="w", pady=(6, 8))
    if message:
        ttk.Label(frame, text=message, foreground="#c0392b").grid(sticky="w", pady=(0, 6))
    entry = ttk.Entry(frame, show="•", width=36)
    entry.grid(sticky="we")
    buttons = ttk.Frame(frame)
    buttons.grid(sticky="e", pady=(12, 0))

    def ok(_=None):
        result["pw"] = entry.get()
        root.destroy()

    def cancel(_=None):
        root.destroy()

    ttk.Button(buttons, text="Cancel", command=cancel).grid(row=0, column=0, padx=(0, 8))
    ttk.Button(buttons, text="Unlock", command=ok).grid(row=0, column=1)
    root.bind("<Return>", ok)
    root.bind("<Escape>", cancel)
    root.protocol("WM_DELETE_WINDOW", cancel)

    root.update_idletasks()
    w, h = root.winfo_width(), root.winfo_height()
    root.geometry(f"+{(root.winfo_screenwidth() - w) // 2}+{(root.winfo_screenheight() - h) // 3}")
    root.lift()
    root.focus_force()
    entry.focus_set()
    root.mainloop()

    if not result["pw"]:
        return 1
    sys.stdout.write(result["pw"] + "\n")
    sys.stdout.flush()
    return 0
