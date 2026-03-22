# gui.py

import tkinter as tk
from tkinter import filedialog, messagebox
from main import analyze_email

def select_file():
    filepath = filedialog.askopenfilename(filetypes=[("Email files", "*.eml *.txt")])
    if filepath:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, filepath)

def run_analysis():
    filepath = file_entry.get()
    if not filepath:
        messagebox.showwarning("Missing File", "Please select a file to analyze.")
        return
    try:
        result = analyze_email(filepath)
        output_box.delete(1.0, tk.END)
        output_box.insert(tk.END, result)
    except Exception as e:
        messagebox.showerror("Error", f"Something went wrong:\n{e}")

root = tk.Tk()
root.title("Phishing Email Analyzer")

# File selection
tk.Label(root, text="Select Email File:").pack(pady=5)
file_frame = tk.Frame(root)
file_frame.pack(padx=10)
file_entry = tk.Entry(file_frame, width=50)
file_entry.pack(side=tk.LEFT, padx=5)
browse_btn = tk.Button(file_frame, text="Browse", command=select_file)
browse_btn.pack(side=tk.LEFT)

# Run analysis
analyze_btn = tk.Button(root, text="Analyze Email", command=run_analysis)
analyze_btn.pack(pady=10)

# Output area
output_box = tk.Text(root, wrap="word", height=25, width=80)
output_box.pack(padx=10, pady=10)

root.mainloop()
