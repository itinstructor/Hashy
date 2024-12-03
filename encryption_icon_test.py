from base64 import b64decode
import tkinter as tk
from encryption_icon import small_icon_data
from encryption_icon import large_icon_data

#small_icon_data = "paste-small-icon-data-here"
#large_icon_data = "paste-large-icon-data-here"

root = tk.Tk()
root.title("Window With Icon")
root.geometry("300x200")

small_icon = tk.PhotoImage(data=b64decode(small_icon_data))
large_icon = tk.PhotoImage(data=b64decode(large_icon_data))
root.iconphoto(False, large_icon, small_icon)

root.mainloop()
