import cv2
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from cryptography.fernet import Fernet
from PIL import Image, ImageTk
class SteganographyApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Steganography App")

        self.img = None
        self.key = None
        self.encrypted_msg = None

        self.create_widgets()

    def create_widgets(self):
        # Styling
        self.master.configure(bg="#F0F0F0")
        self.master.geometry("600x600")

        # Labels and entry widgets
        tk.Label(self.master, text="Enter secret message:", bg="#F0F0F0").grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
        self.msg_entry = tk.Entry(self.master, width=40)
        self.msg_entry.grid(row=0, column=1, padx=10, pady=5, columnspan=2, sticky=tk.W + tk.E)

        tk.Label(self.master, text="Enter password:", bg="#F0F0F0").grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
        self.password_entry = tk.Entry(self.master, show="*", width=40)
        self.password_entry.grid(row=1, column=1, padx=10, pady=5, columnspan=2, sticky=tk.W + tk.E)

        tk.Button(self.master, text="Select Image", command=self.select_image, bg="#4CAF50", fg="white").grid(row=2, column=0, pady=10, sticky=tk.W)
        tk.Button(self.master, text="Encrypt and Embed", command=self.encrypt_and_embed, bg="#008CBA", fg="white").grid(row=2, column=1, pady=10, sticky=tk.W)
        tk.Button(self.master, text="Decrypt and Extract", command=self.decrypt_and_extract, bg="#FFD700").grid(row=2, column=2, pady=10, sticky=tk.W)

        tk.Label(self.master, text="Enter passcode for Decryption:", bg="#F0F0F0").grid(row=3, column=0, columnspan=3, pady=5, sticky=tk.W)
        self.passcode_entry = tk.Entry(self.master, show="*", width=40)
        self.passcode_entry.grid(row=4, column=0, columnspan=3, pady=5, sticky=tk.W + tk.E)

        # Image display
        self.canvas = tk.Canvas(self.master, width=400, height=300, bg="#E0E0E0", relief="raised", borderwidth=2)
        self.canvas.grid(row=5, column=0, columnspan=3, pady=10)

        # Progress label
        tk.Label(self.master, text="Progress:", bg="#F0F0F0").grid(row=6, column=0, pady=5, sticky=tk.W)
        self.progress_label = tk.Label(self.master, text="0%", bg="#F0F0F0")
        self.progress_label.grid(row=6, column=1, pady=5, sticky=tk.W)

        # Log display
        tk.Label(self.master, text="Log:", bg="#F0F0F0").grid(row=7, column=0, pady=5, sticky=tk.W)
        self.log_text = scrolledtext.ScrolledText(self.master, height=6, width=40, wrap=tk.WORD)
        self.log_text.grid(row=7, column=1, columnspan=2, pady=5, sticky=tk.W)

        # Save decrypted message checkbox
        self.save_checkbox_var = tk.IntVar()
        self.save_checkbox = tk.Checkbutton(self.master, text="Save Decrypted Message", variable=self.save_checkbox_var, bg="#F0F0F0")
        self.save_checkbox.grid(row=8, column=0, columnspan=3, pady=5, sticky=tk.W)

        # Save button for decrypted message
        self.save_button = tk.Button(self.master, text="Save Decrypted Message", command=self.save_decrypted_message, bg="#4CAF50", fg="white")
        self.save_button.grid(row=9, column=0, columnspan=3, pady=5, sticky=tk.W)

        # Clear log button
        self.clear_log_button = tk.Button(self.master, text="Clear Log", command=self.clear_log, bg="#FF0000", fg="white")
        self.clear_log_button.grid(row=10, column=0, columnspan=3, pady=5, sticky=tk.W)

        # Status label
        self.status_label = tk.Label(self.master, text="Status: Ready", bg="#F0F0F0")
        self.status_label.grid(row=11, column=0, columnspan=3, pady=5)

    def select_image(self):
        file_path = filedialog.askopenfilename(title="Select Image", filetypes=[("Image files", "*.jpg;*.png")])
        if file_path:
            self.img = cv2.imread(file_path)
            self.display_image(file_path)

    def display_image(self, file_path):
        if self.img is not None:
            img = cv2.cvtColor(self.img, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(img)
            img = ImageTk.PhotoImage(img)
            self.canvas.image = img
            self.canvas.create_image(0, 0, anchor=tk.NW, image=img)
            self.status_label.config(text=f"Status: Image loaded - {os.path.basename(file_path)}")

    def encrypt_and_embed(self):
        msg = self.msg_entry.get()
        password = self.password_entry.get()

        if self.img is None:
            messagebox.showerror("Error", "Image not loaded. Please select an image.")
            return

        if not msg or not password:
            messagebox.showerror("Error", "Please enter a message and password.")
            return

        self.key = Fernet.generate_key()

        encrypted_msg = self.encrypt_message(msg, self.key)
        self.encrypted_msg = encrypted_msg

        # Reset log and progress label
        self.log_text.delete(1.0, tk.END)
        self.progress_label.config(text="0%")

        self.embed_message(self.img, encrypted_msg, self.progress_label, self.log_text)

        cv2.imwrite("Encryptedmsg.jpg", self.img)

        self.status_label.config(text="Status: Encryption and embedding completed. Image saved as 'Encryptedmsg.jpg'.")

    def decrypt_and_extract(self):
        passcode = self.passcode_entry.get()

        if self.img is None or self.key is None or self.encrypted_msg is None:
            messagebox.showerror("Error", "Image or key not available. Please encrypt and embed first.")
            return

        if passcode:
            decrypted_msg = self.extract_and_decrypt_message(self.img, self.key, len(self.encrypted_msg))
            messagebox.showinfo("Decrypted Message", f"The decrypted message is:\n\n{decrypted_msg}")
            self.status_label.config(text="Status: Decryption and extraction completed.")

            # Save decrypted message to a file if checkbox is selected
            if self.save_checkbox_var.get() == 1:
                self.save_decrypted_message()
        else:
            messagebox.showerror("Error", "Passcode not provided.")

    def save_decrypted_message(self):
        if self.encrypted_msg is None:
            messagebox.showerror("Error", "No decrypted message to save.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                file.write(self.encrypted_msg.decode())
            self.status_label.config(text=f"Status: Decrypted message saved to '{os.path.basename(file_path)}'.")

    def clear_log(self):
        self.log_text.delete(1.0, tk.END)
        self.status_label.config(text="Status: Log cleared.")

    def encrypt_message(self, message, key):
        cipher_suite = Fernet(key)
        encrypted_message = cipher_suite.encrypt(message.encode())
        return encrypted_message

    def extract_and_decrypt_message(self, img, key, msg_len):
        cipher_suite = Fernet(key)
        message = ""
        n, m, z = 0, 0, 0

        for i in range(msg_len):
            if n < img.shape[0] and m < img.shape[1] and z < img.shape[2]:
                message += chr(img[n, m, z])
                n += 1
                m += 1
                z = (z + 1) % 3
            else:
                break

        return cipher_suite.decrypt(message.encode()).decode()

    def embed_message(self, img, encrypted_message, progress_label, log_text):
        n, m, z = 0, 0, 0
        total_pixels = img.shape[0] * img.shape[1] * img.shape[2]

        for i in range(len(encrypted_message)):
            if n < img.shape[0] and m < img.shape[1] and z < img.shape[2]:
                img[n, m, z] = encrypted_message[i]
                n += 1
                m += 1
                z = (z + 1) % 3
            else:
                break

            # Update progress label and log
            progress_label.config(text=f"{int((n * m * z / total_pixels) * 100)}%")
            log_text.insert(tk.END, f"Pixel {n * m * z}/{total_pixels}\n")

        # Ensure the log stays at the bottom
        log_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
