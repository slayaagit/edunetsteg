import cv2
import numpy as np
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()[:16]  # Use first 16 chars

def find_edges(img):
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    return cv2.Canny(gray, 50, 150)

def text_to_binary(text):
    return ''.join(format(ord(c), '08b') for c in text)

def binary_to_text(binary_data):
    chars = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    return ''.join(chr(int(c, 2)) for c in chars).strip('\x00')

def hide(img_path, msg, pwd, save_folder):
    img = cv2.imread(img_path)
    if img is None:
        messagebox.showerror("Error", "Invalid image file.")
        return

    edges = find_edges(img)
    h, w = img.shape[:2]

    pwd_hash = hash_password(pwd)
    msg_len = f"{len(msg):04d}"  # Store message length as a 4-digit number
    full_msg = pwd_hash + msg_len + msg
    binary_msg = text_to_binary(full_msg)

    if len(binary_msg) > h * w:
        messagebox.showerror("Error", "Message too long for this image.")
        return

    idx = 0
    for y in range(h):
        for x in range(w):
            if edges[y, x] > 100 and idx < len(binary_msg):
                img[y, x, 0] = (img[y, x, 0] & 0b11111110) | int(binary_msg[idx]) 
                idx += 1

    save_path = f"{save_folder}/encoded_image.png"
    cv2.imwrite(save_path, img)
    messagebox.showinfo("Success", f"Message hidden and saved at {save_path}")


def extract(img_path, pwd):
    img = cv2.imread(img_path)
    if img is None:
        messagebox.showerror("Error", "Invalid image file.")
        return

    edges = find_edges(img)
    h, w = img.shape[:2]

    binary_msg = []
    for y in range(h):
        for x in range(w):
            if edges[y, x] > 100:
                binary_msg.append(str(img[y, x, 0] & 1))

    binary_msg = ''.join(binary_msg)
    extracted_text = binary_to_text(binary_msg)

    if len(extracted_text) >= 20:
        stored_hash, msg_len, hidden_msg = extracted_text[:16], extracted_text[16:20], extracted_text[20:]
        if stored_hash == hash_password(pwd):
            actual_msg = hidden_msg[:int(msg_len)]
            messagebox.showinfo("Extracted Message", f"Message: {actual_msg}")
        else:
            messagebox.showerror("Error", "Incorrect password!")
    else:
        messagebox.showerror("Error", "No hidden message found!")

class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Stego Tool with Drag-and-Drop")
        self.root.geometry("500x500")

        self.tab = tk.Frame(self.root)
        self.tab.pack(pady=10)

        # Hide Message Tab
        self.hide_frame = tk.Frame(self.tab)
        self.hide_frame.pack()

        tk.Label(self.hide_frame, text="Drop Image to Hide Message").pack()

        self.img_var = tk.StringVar()
        self.img_entry = tk.Entry(self.hide_frame, textvariable=self.img_var, width=40, state="readonly")
        self.img_entry.pack()

        self.drop_label = tk.Label(self.hide_frame, text="Drop Image Here", width=40, height=5, relief="ridge", bg="lightgray")
        self.drop_label.pack(pady=5)
        self.drop_label.bind("<Button-1>", self.pick_img)
        self.drop_label.drop_target_register(DND_FILES)
        self.drop_label.dnd_bind("<<Drop>>", self.drop_img)

        tk.Label(self.hide_frame, text="Enter Message:").pack()
        self.msg_entry = tk.Entry(self.hide_frame, width=50)
        self.msg_entry.pack()

        tk.Label(self.hide_frame, text="Enter Password:").pack()
        self.pwd_entry = tk.Entry(self.hide_frame, width=30, show="*")
        self.pwd_entry.pack()

        tk.Button(self.hide_frame, text="Choose Save Folder", command=self.choose_folder).pack()
        self.save_folder_var = tk.StringVar()
        self.folder_label = tk.Label(self.hide_frame, textvariable=self.save_folder_var)
        self.folder_label.pack()

        tk.Button(self.hide_frame, text="Hide", command=self.hide_msg).pack()

        # Extract Message Tab
        self.extract_frame = tk.Frame(self.tab)
        self.extract_frame.pack()

        tk.Label(self.extract_frame, text="Drop Image to Extract Message").pack()

        self.img_dec_var = tk.StringVar()
        self.img_dec_entry = tk.Entry(self.extract_frame, textvariable=self.img_dec_var, width=40, state="readonly")
        self.img_dec_entry.pack()

        self.drop_label_dec = tk.Label(self.extract_frame, text="Drop Image Here", width=40, height=5, relief="ridge", bg="lightgray")
        self.drop_label_dec.pack(pady=5)
        self.drop_label_dec.bind("<Button-1>", self.pick_img_dec)
        self.drop_label_dec.drop_target_register(DND_FILES)
        self.drop_label_dec.dnd_bind("<<Drop>>", self.drop_img_dec)

        tk.Label(self.extract_frame, text="Enter Password:").pack()
        self.pwd_dec_entry = tk.Entry(self.extract_frame, width=30, show="*")
        self.pwd_dec_entry.pack()

        tk.Button(self.extract_frame, text="Extract", command=self.extract_msg).pack()

    def pick_img(self, event=None):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        self.img_var.set(file_path)
        self.drop_label.config(text="Image Selected!")

    def pick_img_dec(self, event=None):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])
        self.img_dec_var.set(file_path)
        self.drop_label_dec.config(text="Image Selected!")

    def drop_img(self, event):
        self.img_var.set(event.data.strip("{}"))
        self.drop_label.config(text="Image Dropped!")

    def drop_img_dec(self, event):
        self.img_dec_var.set(event.data.strip("{}"))
        self.drop_label_dec.config(text="Image Dropped!")

    def choose_folder(self):
        folder_selected = filedialog.askdirectory()
        if folder_selected:
            self.save_folder_var.set(folder_selected)

    def hide_msg(self):
        img_path = self.img_var.get()
        msg = self.msg_entry.get()
        pwd = self.pwd_entry.get()
        save_folder = self.save_folder_var.get()

        if not img_path or not msg or not pwd or not save_folder:
            messagebox.showerror("Error", "Select image, message, password, and save folder.")
            return

        hide(img_path, msg, pwd, save_folder)

    def extract_msg(self):
        img_path = self.img_dec_var.get()
        pwd = self.pwd_dec_entry.get()

        if not img_path or not pwd:
            messagebox.showerror("Error", "Select image and enter password.")
            return

        extract(img_path, pwd)

# Run Application
if __name__ == "__main__":
    root = TkinterDnD.Tk()
    app = StegoApp(root)
    root.mainloop()
