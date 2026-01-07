import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
import tkinter as tk
import os
import random
import hashlib




class CryptographyApp:
    def __init__(self):
        # Initialize the main window
        self.window = ttk.Window(themename="superhero")
        self.window.title("ITRI615 Cryptography Project")
        self.window.geometry("500x400")
        self.window.resizable(False, False)

        # Color
        self.backProf_color = "#f4f4f4" 
        self.txtAndLabProf_color = "#222222" 
        self.buttonsProf_color = "#cccccc" 

        # Font
        self.style = ttk.Style()
        self.style.configure("TLabel", font=("Segoe UI", 10))
        self.style.configure("TButton", font=("Segoe UI", 10))
        self.style.configure("TEntry", font=("Segoe UI", 10))

        # Custom Styles
        self.style.configure("Custom.TLabel", font=("Segoe UI", 10), background=self.backProf_color)

        # File selection section
        file_path_label = ttk.Label(self.window, text="File Path:", style="Custom.TLabel")
        file_path_label.pack(fill="x", padx=20)

        file_path_frame = ttk.Frame(self.window)
        file_path_frame.pack(pady=5)

        self.file_path_entry = ttk.Entry(file_path_frame, width=50)
        self.file_path_entry.pack(side=ttk.LEFT)

        browse_button = ttk.Button(file_path_frame, text="Browse", command=self.browse_file)
        browse_button.pack(side=ttk.LEFT, padx=5)

        # Dropdown menu for selecting encryption type
        encryption_options = [
            "Own Algorithm",
            "Vigenere",
            "Columnar Transposition Cipher",
            "Vernam Cipher (OTP)",
            "Product Cipher"
        ]

        # Variable to hold selected encryption type
        self.encryption_type_var = ttk.StringVar()

        self.encryption_type_combo = ttk.Combobox(
            self.window, textvariable=self.encryption_type_var,
            values=encryption_options, state="readonly"
        )
        
        self.encryption_type_combo.set("Select Encryption Type")
        self.encryption_type_combo.pack(pady=5)

        # Key generation and input section
        key_frame = ttk.Frame(self.window)
        key_frame.pack(pady=10)

        # Checkbox to toggle between manual and automatic key input
        self.toggle_key_entry_var = ttk.BooleanVar(value=False)
        toggle_key_entry_checkbutton = ttk.Checkbutton(key_frame, text="Generate Key?", 
                                                    variable=self.toggle_key_entry_var, 
                                                    command=self.toggle_gen_type)
        toggle_key_entry_checkbutton.pack(side=ttk.LEFT)

        # Dropdown to select security level for generated key
        self.security_level_var = ttk.StringVar(value="Low")
        security_level_label = ttk.Label(key_frame, text="Security Level:")
        security_level_label.pack(side=ttk.LEFT, padx=10)

        self.security_level_menu = ttk.OptionMenu(key_frame, self.security_level_var, 
                                               "Low", "Medium", "High")
        self.security_level_menu.config(state=ttk.DISABLED)
        self.security_level_menu.pack(side=ttk.LEFT)

        # Button to trigger key generation
        self.generate_key_button = ttk.Button(key_frame, text="Generate Key", 
                                           command=self.generate_key)
        self.generate_key_button.config(state=ttk.DISABLED)
        self.generate_key_button.pack(side=ttk.LEFT)

        # Entry box for key input/display
        self.key_entry = ttk.Entry(self.window, width=50, state=ttk.NORMAL)
        self.key_entry.pack(pady=5)

        # Buttons to trigger encryption and decryption
        encryption_frame = ttk.Frame(self.window)
        encryption_frame.pack(pady=10)

        encrypt_button = ttk.Button(encryption_frame, text="Encrypt", style="primary.TButton", command=self.decide_enc)
        encrypt_button.pack(side=ttk.LEFT, padx=5)

        decrypt_button = ttk.Button(encryption_frame, text="Decrypt", style="danger.TButton", command=self.decide_dec)
        decrypt_button.pack(side=ttk.LEFT, padx=5)

    def run(self):
        # Start the GUI application loop
        self.window.mainloop()

    def browse_file(self):
        # Open file dialog to select a file
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path_entry.delete(0, ttk.END)
            self.file_path_entry.insert(0, file_path)

    def toggle_gen_type(self):
        # Enable or disable key generation UI based on checkbox state
        if self.toggle_key_entry_var.get():
            self.key_entry.config(state=ttk.DISABLED)
            self.security_level_menu.config(state=ttk.NORMAL)
            self.generate_key_button.config(state=ttk.NORMAL)

             # Reset the security level menu to always have Low, Medium, High
            levels = ["Low", "Medium", "High"]
            self.security_level_menu["menu"].delete(0, "end")
            for level in levels:
                self.security_level_menu["menu"].add_command(
                    label=level, 
                    command=lambda l=level: self.security_level_var.set(l)
                )

        else:
            self.key_entry.config(state=ttk.NORMAL)
            self.key_entry.delete(0, ttk.END)
            self.security_level_menu.config(state=ttk.DISABLED)
            self.generate_key_button.config(state=ttk.DISABLED)

    def generate_key(self):
        # Generate a key based on selected encryption type and security level
        security_level = self.security_level_var.get()
        encryption_type = self.encryption_type_var.get()

        try:
            # Key generation for Own Algorithm (Numeric Key)
            if encryption_type == "Own Algorithm":
                if security_level == "Low":
                    key = random.randint(1, 100)
                elif security_level == "Medium":
                    key = random.randint(101, 10000)
                else:
                    key = random.randint(10001, 1000000)

            # Key generation for Columnar Transposition Cipher (Pronounceable)
            elif encryption_type == "Columnar Transposition Cipher":
                vowels = 'aeiou'
                consonants = 'bcdfghjklmnpqrstvwxyz'
                key_lengths = {"Low": 5, "Medium": 8, "High": 12}  # Use longer lengths for better security
                length = key_lengths[security_level]

                # Generate a pronounceable key
                key = ''.join(
                    random.choice(consonants) + random.choice(vowels)
                    for _ in range(length // 2)
                )

                # Ensure the key is exactly the right length
                if len(key) < length:
                    key += random.choice(consonants)

            # Key generation for Vernam Cipher (OTP)
            elif encryption_type == "Vernam Cipher (OTP)":
                file_path = self.file_path_entry.get()
                if not file_path:
                    messagebox.showerror("Error", "Please select a file before generating a key for Vernam Cipher (OTP)!")
                    return
                
                # Read the file to determine required key length
                with open(file_path, 'rb') as f:
                    plaintext = f.read()
                    plaintext_length = len(plaintext)

                # Set key length based on security level
                if security_level == "Low":
                    key_length = max(plaintext_length, 16)  # Minimum 16 bytes (128 bits)
                elif security_level == "Medium":
                    key_length = max(plaintext_length, 32)  # Minimum 32 bytes (256 bits)
                else:
                    key_length = max(plaintext_length, 64)  # Minimum 64 bytes (512 bits)

                # Generate a key of the determined length
                key = ''.join(random.choices(
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()',
                    k=key_length
                ))

            # Default key generation for other ciphers
            else:
                key_lengths = {"Low": 5, "Medium": 10, "High": 20}
                length = key_lengths[security_level]
                key = ''.join(random.choices(
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
                    k=length
                ))

            # Update the key entry field
            self.current_key = key
            self.key_entry.config(state=ttk.NORMAL)
            self.key_entry.delete(0, ttk.END)
            self.key_entry.insert(0, str(key))
            self.key_entry.config(state=ttk.DISABLED)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate key: {e}")


    def decide_enc(self):
        # Trigger encryption based on selected encryption type
        if not self.validate_inputs():
            return
        algo = self.encryption_type_var.get()
        if algo == "Own Algorithm":
            self.own_algorithm_encrypt()
        elif algo == "Vigenere":
            self.vigenere_encrypt()
        elif algo == "Columnar Transposition Cipher":
            self.columnar_transposition_encrypt()
        elif algo == "Vernam Cipher (OTP)":
            self.vernam_cipher_encrypt()
        elif algo == "Product Cipher":
            self.product_cipher_encrypt()
        else:
            messagebox.showerror("Error", "Unsupported encryption type selected.")

    def decide_dec(self):
        # Trigger decryption based on selected encryption type
        if not self.validate_inputs():
            return
        algo = self.encryption_type_var.get()
        if algo == "Own Algorithm":
            self.own_algorithm_decrypt()
        elif algo == "Vigenere":
            self.vigenere_decrypt()
        elif algo == "Columnar Transposition Cipher":
            self.columnar_transposition_decrypt()
        elif algo == "Vernam Cipher (OTP)":
            self.vernam_cipher_decrypt()
        elif algo == "Product Cipher":
            self.product_cipher_decrypt()
        else:
            messagebox.showerror("Error", "Unsupported decryption type selected.")

    def validate_inputs(self):
        # Check if file is selected and a valid key is provided
        in_filename = self.file_path_entry.get()
        if not in_filename:
            messagebox.showerror("Error", "Please select a file!")
            return False
        if not self.toggle_key_entry_var.get():
            key = self.key_entry.get()
            if not key:
                messagebox.showerror("Error", "Please enter a key!")
                return False
            if self.encryption_type_var.get() == "Own Algorithm" and not key.isdigit():
                messagebox.showerror("Error", "For Own Algorithm, key must be a number!")
                return False
        else:
            if not hasattr(self, 'current_key'):
                messagebox.showerror("Error", "Please generate a key first!")
                return False
        return True

    def own_algorithm_encrypt(self):
        # Encrypt file using custom algorithm with numeric key
        in_filename = self.file_path_entry.get()
        out_filename = in_filename + ".enc"
        shift = int(self.current_key if self.toggle_key_entry_var.get() else self.key_entry.get())
        key_bytes = shift.to_bytes((shift.bit_length() + 7) // 8, byteorder='big') or b'\x01'
        salt = os.urandom(16)

        try:
            with open(in_filename, 'rb') as infile, open(out_filename, 'wb') as outfile:
                
                outfile.write(len(key_bytes).to_bytes(1, 'big'))# Store key for verification
                outfile.write(key_bytes)
                outfile.write(salt)

                mixed_key = bytearray((k ^ s) for k, s in zip(key_bytes * (16 // len(key_bytes) + 1), salt))
                while True:
                    chunk = infile.read(1024)
                    if not chunk:
                        break

                    encrypted_chunk = bytearray()
                    for i, byte in enumerate(chunk):
                        key_byte = mixed_key[i % len(mixed_key)]
                        shifted = (byte + key_byte) % 256
                        xored = shifted ^ ((key_byte * 73 + 41) % 256)
                        encrypted_chunk.append(xored)

                    outfile.write(encrypted_chunk)

            os.remove(in_filename)
            messagebox.showinfo("Success", f"File encrypted using Custom Algorithm!\nSaved to: {out_filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def own_algorithm_decrypt(self):
         # Decrypt file using custom algorithm
        in_filename = self.file_path_entry.get()
        out_filename = in_filename.replace(".enc", "")
        user_key = int(self.current_key if self.toggle_key_entry_var.get() else self.key_entry.get())
        user_key_bytes = user_key.to_bytes((user_key.bit_length() + 7) // 8, byteorder='big') or b'\x01'

        try:
            with open(in_filename, 'rb') as infile, open(out_filename, 'wb') as outfile:
                # Read and validate the stored key
                key_len = int.from_bytes(infile.read(1), 'big')
                stored_key_bytes = infile.read(key_len)
                salt = infile.read(16)

                if stored_key_bytes != user_key_bytes:
                    messagebox.showerror("Error", "Incorrect decryption key!")
                    return

                mixed_key = bytearray((k ^ s) for k, s in zip(stored_key_bytes * (16 // len(stored_key_bytes) + 1), salt))

                while True:
                    chunk = infile.read(1024)
                    if not chunk:
                        break

                    decrypted_chunk = bytearray()
                    for i, byte in enumerate(chunk):
                        key_byte = mixed_key[i % len(mixed_key)]
                        unxored = byte ^ ((key_byte * 73 + 41) % 256)
                        original = (unxored - key_byte) % 256
                        decrypted_chunk.append(original)

                    outfile.write(decrypted_chunk)

            os.remove(in_filename)
            messagebox.showinfo("Success", f"File decrypted using Custom Algorithm!\nSaved to: {out_filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def vigenere_encrypt(self):
         # Get the input file path from the GUI entry field
        in_filename = self.file_path_entry.get()
         # Define the output filename by appending ".enc"
        out_filename = in_filename + ".enc"
         # Use the current key from memory if the toggle is on, otherwise use the entered key
        key = self.current_key if self.toggle_key_entry_var.get() else self.key_entry.get()

        try:
             # Convert the key to bytes for byte-wise encryption
            key_bytes = key.encode('utf-8')
            
            # Open input file in binary read mode, and output file in binary write mode
            with open(in_filename, 'rb') as infile, open(out_filename, 'wb') as outfile:
                # Write the length of the key (4 bytes) followed by the key itself to the output file
                # This is used during decryption to verify the correct key is used
                # Store the key itself (not just length) for verification
                outfile.write(len(key_bytes).to_bytes(4, 'big'))  # Track position within key
                outfile.write(key_bytes)
                
                key_index = 0
                while True:
                    chunk = infile.read(1024)    # Read 1024-byte chunks from the file
                    if not chunk:
                        break
                    encrypted_chunk = bytearray()  # Container for encrypted bytes
                    for byte in chunk:
                        key_byte = key_bytes[key_index % len(key_bytes)]
                        encrypted_chunk.append((byte + key_byte) % 256)
                        key_index += 1
                    outfile.write(encrypted_chunk)
            os.remove(in_filename) # Delete the original file after encryption
            messagebox.showinfo("Success", f"File encrypted using Vigenere cipher!\nSaved to: {out_filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def vigenere_decrypt(self):
        # Get the encrypted file path from the GUI entry
        in_filename = self.file_path_entry.get()
           # Define output file by removing ".enc" extension
        out_filename = in_filename.replace(".enc", "")
        # Use the current key if toggle is on, otherwise use the input key
        key = self.current_key if self.toggle_key_entry_var.get() else self.key_entry.get()

        try:
            key_bytes = key.encode('utf-8')
            # Read first 4 bytes to get length of stored key
            with open(in_filename, 'rb') as infile, open(out_filename, 'wb') as outfile:
                # Read stored key length and key
                stored_key_length = int.from_bytes(infile.read(4), 'big')
                 # Read the actual stored key from file
                stored_key = infile.read(stored_key_length)
                  # Compare stored key with input key; abort if mismatch
                if stored_key != key_bytes:
                    #"Warning: Vigenere key mismatch - skipping check for Product Cipher"
                    pass
                    
                key_index = 0
                while True:
                    chunk = infile.read(1024) # Read encrypted data in chunks
                    if not chunk:
                        break                # Exit on end of file
                    decrypted_chunk = bytearray()
                    for byte in chunk:
                        key_byte = key_bytes[key_index % len(key_bytes)]  
                        decrypted_chunk.append((byte - key_byte) % 256)   # Decrypt using modular subtraction and wrap around 256
                        key_index += 1
                    outfile.write(decrypted_chunk)  # Write decrypted bytes
            os.remove(in_filename)                  # Delete encrypted file after decryption
            messagebox.showinfo("Success", f"File decrypted using Vigenere cipher!\nSaved to: {out_filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}") # Show error message if decryption fails

    def columnar_transposition_encrypt(self):
        in_filename = self.file_path_entry.get()
        out_filename = in_filename + ".enc"
        key = self.current_key if self.toggle_key_entry_var.get() else self.key_entry.get()

        try:
            with open(in_filename, 'rb') as infile:
                # STEP 1: Read and preserve Vigenère metadata
                meta = infile.read(4)  # First 4 bytes = key length
                key_len = int.from_bytes(meta, 'big')
                key_bytes = infile.read(key_len)
                meta += key_bytes

                # STEP 2: Read the actual file content
                plaintext = infile.read()

            key_hash = hashlib.sha256(key.encode()).digest()
            key_order = list(key_hash)
            num_cols = len(key_order)

            # Add random salt
            salt = os.urandom(16)
            salted_plaintext = salt + plaintext

            # Calculate padding length (PKCS7)
            pad_length = num_cols - (len(salted_plaintext) % num_cols)
            if pad_length == num_cols:
                pad_length = 0  # No padding needed if already a multiple
            padding = bytes([pad_length] * pad_length)
            padded_plaintext = salted_plaintext + padding

            # Create columns based on the key order
            ciphertext = bytearray()
            sorted_key_indices = sorted(range(num_cols), key=lambda i: key_order[i])
            for col_index in sorted_key_indices:
                for i in range(col_index, len(padded_plaintext), num_cols):
                    ciphertext.append(padded_plaintext[i])

            # Store metadata: key hash length, key hash, salt length, salt
            with open(out_filename, 'wb') as outfile:
                outfile.write(len(key_hash).to_bytes(4, 'big'))
                outfile.write(key_hash)
                outfile.write(len(salt).to_bytes(4, 'big'))
                outfile.write(salt)
                outfile.write(ciphertext)

            os.remove(in_filename)
            messagebox.showinfo("Success", f"File encrypted using Columnar Transposition!\nSaved to: {out_filename}")

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def columnar_transposition_decrypt(self):
        in_filename = self.file_path_entry.get()
        out_filename = in_filename.replace(".enc", "")
        key = self.current_key if self.toggle_key_entry_var.get() else self.key_entry.get()

        try:
            with open(in_filename, 'rb') as infile:
                # Read metadata
                key_hash_length = int.from_bytes(infile.read(4), 'big')
                stored_key_hash = infile.read(key_hash_length)
                salt_length = int.from_bytes(infile.read(4), 'big')
                salt = infile.read(salt_length)
                ciphertext = infile.read()

            # Verify key
            key_hash = hashlib.sha256(key.encode()).digest()
            if key_hash != stored_key_hash:
                messagebox.showerror("Error", "Incorrect decryption key!")
                return

            num_cols = len(stored_key_hash)
            num_rows = len(ciphertext) // num_cols
            if len(ciphertext) % num_cols != 0:
                num_rows += 1

            # Create a grid for reconstruction
            grid = [[None for _ in range(num_cols)] for _ in range(num_rows)]
            
            # Get the order of columns for decryption
            key_order = list(stored_key_hash)
            sorted_cols = sorted(range(num_cols), key=lambda i: key_order[i])

            # Fill the grid column by column in the original order
            index = 0
            for col in sorted_cols:
                for row in range(num_rows):
                    if index < len(ciphertext):
                        grid[row][col] = ciphertext[index]
                        index += 1
                    else:
                        # Handle padding if needed
                        grid[row][col] = 0

            # Read the grid row by row to reconstruct the plaintext
            plaintext = bytearray()
            for row in range(num_rows):
                for col in range(num_cols):
                    if grid[row][col] is not None:
                        plaintext.append(grid[row][col])

            # Remove padding (PKCS7 style)
            if plaintext:
                pad_length = plaintext[-1]
                if pad_length > 0 and pad_length <= num_cols:
                    # Verify padding
                    if all(byte == pad_length for byte in plaintext[-pad_length:]):
                        plaintext = plaintext[:-pad_length]

            # Remove salt
            decrypted_data = plaintext[salt_length:]

            with open(out_filename, 'wb') as outfile:
                outfile.write(decrypted_data)

            os.remove(in_filename)
            messagebox.showinfo("Success", f"File decrypted using Columnar Transposition!\nSaved to: {out_filename}")

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def vernam_cipher_encrypt(self):
        in_filename = self.file_path_entry.get()
        out_filename = in_filename + ".enc"
        key = self.current_key if self.toggle_key_entry_var.get() else self.key_entry.get()

        try:
            # Ensure the key length is at least as long as the file content
            with open(in_filename, 'rb') as infile:
                plaintext = infile.read()

            if len(key) < len(plaintext):
                messagebox.showerror("Error", "Key must be at least as long as the plaintext for Vernam Cipher!")
                return

            # Encrypt using XOR
            encrypted_bytes = bytearray()
            for i in range(len(plaintext)):
                encrypted_bytes.append(plaintext[i] ^ ord(key[i]))

            with open(out_filename, 'wb') as outfile:
                outfile.write(encrypted_bytes)

            os.remove(in_filename)
            messagebox.showinfo("Success", f"File encrypted using Vernam Cipher (OTP)!\nSaved to: {out_filename}")

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def vernam_cipher_decrypt(self):
        in_filename = self.file_path_entry.get()
        out_filename = in_filename.replace(".enc", "")
        key = self.current_key if self.toggle_key_entry_var.get() else self.key_entry.get()

        try:
            # Ensure the key length is at least as long as the ciphertext
            with open(in_filename, 'rb') as infile:
                ciphertext = infile.read()

            if len(key) < len(ciphertext):
                messagebox.showerror("Error", "Key must be at least as long as the ciphertext for Vernam Cipher!")
                return

            # Decrypt using XOR
            decrypted_bytes = bytearray()
            for i in range(len(ciphertext)):
                decrypted_bytes.append(ciphertext[i] ^ ord(key[i]))

            with open(out_filename, 'wb') as outfile:
                outfile.write(decrypted_bytes)

            os.remove(in_filename)
            messagebox.showinfo("Success", f"File decrypted using Vernam Cipher (OTP)!\nSaved to: {out_filename}")

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    def product_cipher_encrypt(self):
        in_filename = self.file_path_entry.get()
        out_filename_stage1 = in_filename + ".vigenere"
        final_out_filename = in_filename + ".enc"
        key = self.current_key if self.toggle_key_entry_var.get() else self.key_entry.get()

        try:
            # --- Step 1: Vigenère Encryption ---
            key_bytes = key.encode('utf-8')
            with open(in_filename, 'rb') as infile, open(out_filename_stage1, 'wb') as stage1:
                stage1.write(len(key_bytes).to_bytes(4, 'big'))
                stage1.write(key_bytes)
                key_index = 0
                while True:
                    chunk = infile.read(1024)
                    if not chunk:
                        break
                    encrypted_chunk = bytearray()
                    for byte in chunk:
                        key_byte = key_bytes[key_index % len(key_bytes)]
                        encrypted_chunk.append((byte + key_byte) % 256)
                        key_index += 1
                    stage1.write(encrypted_chunk)

            # --- Step 2: Columnar Transposition Encryption ---
            self.file_path_entry.delete(0, ttk.END)
            self.file_path_entry.insert(0, out_filename_stage1)
            self.columnar_transposition_encrypt()

            # Cleanup intermediate file
            if os.path.exists(out_filename_stage1):
                os.remove(out_filename_stage1)

        except Exception as e:
            messagebox.showerror("Error", f"Product cipher encryption failed: {e}")
        
        
    def product_cipher_decrypt(self):
        in_filename = self.file_path_entry.get()
        out_filename_stage1 = in_filename.replace(".enc", ".vigenere")
        final_out_filename = in_filename.replace(".enc", "")
        key = self.current_key if self.toggle_key_entry_var.get() else self.key_entry.get()

        try:
            # --- Step 1: Columnar Transposition Decryption ---
            self.columnar_transposition_decrypt()

            # Now the decrypted file should be: .vigenere
            decrypted_file = final_out_filename
            self.file_path_entry.delete(0, ttk.END)
            self.file_path_entry.insert(0, decrypted_file)

            # --- Step 2: Vigenère Decryption ---
            self.vigenere_decrypt()

            # Cleanup intermediate file
            if os.path.exists(decrypted_file):
                os.remove(decrypted_file)

        except Exception as e:
            messagebox.showerror("Error", f"Product cipher decryption failed: {e}")
     
    

# Run the application
if __name__ == "__main__":
    app = CryptographyApp()
    app.run()
