import tkinter as tk
from tkinter import messagebox, filedialog
from encryption import aes_encrypt, aes_decrypt, des_encrypt, des_decrypt, rsa_encrypt, rsa_decrypt, generate_rsa_keys

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption and Decryption App")
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Text").grid(row=0, column=0, padx=10, pady=10)
        self.text_entry = tk.Entry(self.root, width=50)
        self.text_entry.grid(row=0, column=1, padx=10, pady=10)

        tk.Label(self.root, text="Key").grid(row=1, column=0, padx=10, pady=10)
        self.key_entry = tk.Entry(self.root, width=50)
        self.key_entry.grid(row=1, column=1, padx=10, pady=10)

        self.algo_var = tk.StringVar(value="AES")
        tk.Label(self.root, text="Algorithm").grid(row=2, column=0, padx=10, pady=10)
        tk.OptionMenu(self.root, self.algo_var, "AES", "DES", "RSA").grid(row=2, column=1, padx=10, pady=10)

        tk.Button(self.root, text="Encrypt", command=self.encrypt_text).grid(row=3, column=0, padx=10, pady=10)
        tk.Button(self.root, text="Decrypt", command=self.decrypt_text).grid(row=3, column=1, padx=10, pady=10)
        tk.Button(self.root, text="Generate RSA Keys", command=self.generate_rsa_keys).grid(row=4, column=0, columnspan=2, padx=10, pady=10)

        tk.Label(self.root, text="Output").grid(row=5, column=0, padx=10, pady=10)
        self.output_entry = tk.Entry(self.root, width=50)
        self.output_entry.grid(row=5, column=1, padx=10, pady=10)

    def encrypt_text(self):
        text = self.text_entry.get()
        key = self.key_entry.get().encode()
        algorithm = self.algo_var.get()

        try:
            if algorithm == "AES":
                if len(key) not in (16, 24, 32):
                    raise ValueError("AES key must be 16, 24, or 32 bytes long")
                encrypted_text = aes_encrypt(text, key)
            elif algorithm == "DES":
                if len(key) != 8:
                    raise ValueError("DES key must be 8 bytes long")
                encrypted_text = des_encrypt(text, key)
            elif algorithm == "RSA":
                encrypted_text = rsa_encrypt(text, key)
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, encrypted_text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_text(self):
        text = self.output_entry.get()
        key = self.key_entry.get().encode()
        algorithm = self.algo_var.get()

        try:
            if algorithm == "AES":
                decrypted_text = aes_decrypt(text, key)
            elif algorithm == "DES":
                decrypted_text = des_decrypt(text, key)
            elif algorithm == "RSA":
                decrypted_text = rsa_decrypt(text, key)
            self.text_entry.delete(0, tk.END)
            self.text_entry.insert(0, decrypted_text)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def generate_rsa_keys(self):
        private_key, public_key = generate_rsa_keys()
        private_key_file = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")], title="Save Private Key")
        public_key_file = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")], title="Save Public Key")

        with open(private_key_file, 'wb') as pkf:
            pkf.write(private_key)

        with open(public_key_file, 'wb') as pkf:
            pkf.write(public_key)

        messagebox.showinfo("Success", "RSA Keys generated and saved successfully")

if __name__ == '__main__':
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
