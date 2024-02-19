# import tkinter as tk
# from tkinter import filedialog, messagebox
# import requests
# import os
# import base64
# from aes import aes_encrypt, aes_decrypt, aes_generate_key
#
#
# class MainApplication(tk.Tk):
#     def __init__(self):
#         super().__init__()
#         self.title("File Sharing App")
#         self.geometry("400x300")
#
#         self.current_screen = None
#         self.access_token = None
#         self.show_start_screen()
#
#     def show_start_screen(self):
#         if self.current_screen:
#             self.current_screen.destroy()
#
#         self.current_screen = StartScreen(self)
#         self.current_screen.pack(fill=tk.BOTH, expand=True)
#
#     def show_register_screen(self):
#         if self.current_screen:
#             self.current_screen.destroy()
#
#         self.current_screen = RegisterScreen(self)
#         self.current_screen.pack(fill=tk.BOTH, expand=True)
#
#     def show_login_screen(self):
#         if self.current_screen:
#             self.current_screen.destroy()
#
#         self.current_screen = LoginScreen(self)
#         self.current_screen.pack(fill=tk.BOTH, expand=True)
#
#     def show_file_select_screen(self):
#         if self.current_screen:
#             self.current_screen.destroy()
#
#         self.current_screen = FileSelectScreen(self)
#         self.current_screen.pack(fill=tk.BOTH, expand=True)
#
#     def register(self, username, password, email):
#         register_data = {'username': username, 'password': password, 'email': email}
#         response = requests.post(f'{base_url}/register', json=register_data)
#         if response.status_code == 201:
#             messagebox.showinfo("Success", "Registration successful!")
#             self.show_login_screen()
#         else:
#             messagebox.showerror("Error", response.json().get('error', 'Registration failed'))
#
#     def login(self, username, password):
#         login_data = {'username': username, 'password': password}
#         response = requests.post(f'{base_url}/login', json=login_data)
#         if response.status_code == 200:
#             self.access_token = response.json().get('access_token')
#             messagebox.showinfo("Success", "Login successful!")
#             self.show_file_select_screen()
#         else:
#             messagebox.showerror("Error", response.json().get('error', 'Login failed'))
#
#     def get_aes_key_from_server(self):
#         headers = {'Authorization': f'Bearer {self.access_token}'}
#         response = requests.get(f'{base_url}/aes_key', headers=headers)
#         if response.status_code == 200:
#             return response.json().get('aes_key')
#         else:
#             return None
#
#
# class StartScreen(tk.Frame):
#     def __init__(self, master):
#         super().__init__(master)
#
#         self.master = master
#
#         tk.Button(self, text="Register", command=self.master.show_register_screen).pack(pady=10)
#         tk.Button(self, text="Login", command=self.master.show_login_screen).pack(pady=10)
#
#
# class RegisterScreen(tk.Frame):
#     def __init__(self, master):
#         super().__init__(master)
#
#         self.master = master
#
#         tk.Label(self, text="Registration", font=("Helvetica", 16)).pack(pady=10)
#
#         self.username_entry = tk.Entry(self, width=30)
#         self.username_entry.pack(pady=5)
#         tk.Label(self, text="Username").pack()
#
#         self.password_entry = tk.Entry(self, width=30, show="*")
#         self.password_entry.pack(pady=5)
#         tk.Label(self, text="Password").pack()
#
#         self.email_entry = tk.Entry(self, width=30)
#         self.email_entry.pack(pady=5)
#         tk.Label(self, text="Email").pack()
#
#         tk.Button(self, text="Register", command=self.register).pack(pady=10)
#
#     def register(self):
#         username = self.username_entry.get()
#         password = self.password_entry.get()
#         email = self.email_entry.get()
#
#         if username and password and email:
#             self.master.register(username, password, email)
#         else:
#             messagebox.showerror("Error", "Please fill in all fields.")
#
#
# class LoginScreen(tk.Frame):
#     def __init__(self, master):
#         super().__init__(master)
#
#         self.master = master
#
#         tk.Label(self, text="Login", font=("Helvetica", 16)).pack(pady=10)
#
#         self.username_entry = tk.Entry(self, width=30)
#         self.username_entry.pack(pady=5)
#         tk.Label(self, text="Username").pack()
#
#         self.password_entry = tk.Entry(self, width=30, show="*")
#         self.password_entry.pack(pady=5)
#         tk.Label(self, text="Password").pack()
#
#         tk.Button(self, text="Login", command=self.login).pack(pady=10)
#
#     def login(self):
#         username = self.username_entry.get()
#         password = self.password_entry.get()
#
#         if username and password:
#             self.master.login(username, password)
#         else:
#             messagebox.showerror("Error", "Please fill in all fields.")
#
#
# class FileSelectScreen(tk.Frame):
#     def __init__(self, master):
#         super().__init__(master)
#
#         self.master = master
#
#         tk.Label(self, text="Select file for encryption/decryption", font=("Helvetica", 16)).pack(pady=10)
#
#         self.file_path_label = tk.Label(self, text="")
#         self.file_path_label.pack(pady=5)
#
#         tk.Button(self, text="Select file", command=self.select_file).pack(pady=5)
#         tk.Button(self, text="Encrypt", command=self.encrypt_file).pack(pady=5)
#         tk.Button(self, text="Decrypt", command=self.decrypt_file).pack(pady=5)
#         tk.Button(self, text="Back", command=self.go_back).pack(pady=5)
#
#         self.file_path = None
#
#     def select_file(self):
#         self.file_path = filedialog.askopenfilename()
#         if self.file_path:
#             self.file_path_label.config(text=f"Selected file:\n{self.file_path}")
#         else:
#             messagebox.showwarning("Warning", "No file selected.")
#
#     def go_back(self):
#         self.master.show_start_screen()
#
#     def encrypt_file(self):
#         if not self.file_path:
#             messagebox.showerror("Error", "No file selected.")
#             return
#
#         aes_key = aes_generate_key()
#
#         with open(self.file_path, 'rb') as file:
#             file_data = file.read()
#
#         encrypted_data = aes_encrypt(file_data, aes_key)
#
#         encrypted_file_path = f'encrypted_{os.path.basename(self.file_path)}'
#         with open(encrypted_file_path, 'wb') as file:
#             file.write(encrypted_data)
#
#         messagebox.showinfo("Encryption complete", f"File encrypted and saved as {encrypted_file_path}")
#
#     def decrypt_file(self):
#         if not self.file_path:
#             messagebox.showerror("Error", "No file selected.")
#             return
#
#         aes_key = self.master.get_aes_key_from_server()
#
#         if aes_key:
#             with open(self.file_path, 'rb') as file:
#                 encrypted_data = file.read()
#
#             decrypted_data = aes_decrypt(encrypted_data, aes_key)
#
#             decrypted_file_path = f'decrypted_{os.path.basename(self.file_path)}'
#             with open(decrypted_file_path, 'wb') as file:
#                 file.write(decrypted_data)
#
#             messagebox.showinfo("Decryption complete", f"File decrypted and saved as {decrypted_file_path}")
#         else:
#             messagebox.showerror("Error", "Failed to retrieve AES key for decryption from the server.")
#
#
# if __name__ == "__main__":
#     base_url = 'http://127.0.0.1:5000'
#     app = MainApplication()
#     app.mainloop()

