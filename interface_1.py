import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import requests

from dlyadiploma.aes import aes_encrypt, aes_decrypt
from rsa import rsa_generate_key_pair, rsa_decrypt_text
from io import BytesIO


class CloudStorageApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Хмарне Сховище")

        self.register_button = tk.Button(root, text="Реєстрація", command=self.open_register_window)
        self.register_button.pack(pady=10)

        self.login_button = tk.Button(root, text="Вхід", command=self.open_login_window)
        self.login_button.pack(pady=10)

        self.username = None
        self.access_token = None

    def open_register_window(self):
        self.root.withdraw()
        self.register_window = tk.Toplevel()

        self.register_window.protocol("WM_DELETE_WINDOW", self.close_register_window)

        self.register_window.title("Реєстрація")

        self.username_label = tk.Label(self.register_window, text="Ім'я користувача:")
        self.username_label.grid(row=0, column=0, sticky="e")
        self.username_entry = tk.Entry(self.register_window)
        self.username_entry.grid(row=0, column=1)

        self.password_label = tk.Label(self.register_window, text="Пароль:")
        self.password_label.grid(row=1, column=0, sticky="e")
        self.password_entry = tk.Entry(self.register_window, show="*")
        self.password_entry.grid(row=1, column=1)

        self.email_label = tk.Label(self.register_window, text="Email:")
        self.email_label.grid(row=2, column=0, sticky="e")
        self.email_entry = tk.Entry(self.register_window)
        self.email_entry.grid(row=2, column=1)

        self.register_button = tk.Button(self.register_window, text="Зареєструватися", command=self.register)
        self.register_button.grid(row=3, column=0, columnspan=2, pady=10)

        self.back_button = tk.Button(self.register_window, text="Назад", command=self.close_register_window)
        self.back_button.grid(row=4, column=0, columnspan=2, pady=10)

    def open_login_window(self):
        self.root.withdraw()
        self.login_window = tk.Toplevel()

        self.login_window.protocol("WM_DELETE_WINDOW", self.close_login_window)

        self.login_window.title("Вхід")

        self.username_label = tk.Label(self.login_window, text="Ім'я користувача:")
        self.username_label.grid(row=0, column=0, sticky="e")
        self.username_entry = tk.Entry(self.login_window)
        self.username_entry.grid(row=0, column=1)

        self.password_label = tk.Label(self.login_window, text="Пароль:")
        self.password_label.grid(row=1, column=0, sticky="e")
        self.password_entry = tk.Entry(self.login_window, show="*")
        self.password_entry.grid(row=1, column=1)

        self.login_button = tk.Button(self.login_window, text="Увійти", command=self.login)
        self.login_button.grid(row=2, column=0, columnspan=2, pady=10)

        self.back_button = tk.Button(self.login_window, text="Назад", command=self.close_login_window)
        self.back_button.grid(row=3, column=0, columnspan=2, pady=10)

    def close_register_window(self):
        self.register_window.destroy()
        self.root.deiconify()

    def close_login_window(self):
        self.login_window.destroy()
        self.root.deiconify()

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        email = self.email_entry.get()

        data = {'username': username, 'password': password, 'email': email}
        response = requests.post('https://9b05-213-200-40-238.ngrok-free.app/register', json=data)

        if response.status_code == 201:
            messagebox.showinfo("Успіх", "Реєстрація пройшла успішно! Перевірте вашу пошту для підтвердження.")
            self.close_register_window()
            # self.open_confirmation_window(email)
        else:
            messagebox.showerror("Помилка", "Не вдалося зареєструватися.")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        data = {'username': username, 'password': password}
        response = requests.post('https://9b05-213-200-40-238.ngrok-free.app/login', json=data)

        if response.status_code == 200:
            messagebox.showinfo("Успіх", "Вхід виконано успішно!")
            self.username = username
            self.access_token = response.json().get('access_token')
            self.close_login_window()
            self.open_files_window()
        else:
            messagebox.showerror("Помилка", "Невірне ім'я користувача або пароль.")

    def open_files_window(self):
        self.root.withdraw()
        self.files_window = tk.Toplevel()
        self.files_window.title("Список файлів")

        headers = {'Authorization': f'Bearer {self.access_token}'}
        response = requests.get(f'https://9b05-213-200-40-238.ngrok-free.app/files/{self.username}',
                                headers=headers)

        if response.status_code == 200:
            files = response.json().get('files')

            self.files_label = tk.Label(self.files_window, text="Список завантажених файлів:")
            self.files_label.pack()

            for file in files:
                file_name = file.split('_')[-1]
                file_button = tk.Button(self.files_window, text=f"{file_name} ⬇️",
                                        command=lambda filename=file: self.request_code(filename))
                file_button.pack(pady=5)

        else:
            messagebox.showerror("Помилка", "Помилка Мережі.")

        select_file_button = tk.Button(self.files_window, text="Обрати файл", command=self.open_file_selection_window)
        select_file_button.pack(pady=10)

    def close_files_window(self):
        self.files_window.destroy()
        self.root.deiconify()

    def request_code(self, filename):
        code = simpledialog.askstring("Введення коду", f"Введіть код для файлу {filename}:")
        if code is not None:
            private_key, public_key = rsa_generate_key_pair()
            data = {'public_key': public_key, 'code': code}
            headers = {'Authorization': f'Bearer {self.access_token}'}

            response = requests.post(f'https://9b05-213-200-40-238.ngrok-free.app/download/{filename}', headers=headers, json=data)
            if response.status_code == 200:
                encrypted_aes_key = response.headers.get('encrypted_aes_key')
                aes_key = rsa_decrypt_text(private_key, encrypted_aes_key)

                with open(f'downloaded_file_{filename}', 'wb') as file:
                    file.write(aes_decrypt(response.content, aes_key))
                messagebox.showinfo("Успіх", f"Файл {filename} успішно завантажено!")
            else:
                messagebox.showerror("Помилка", "Не вдалося завантажити файл.")

    def open_file_selection_window(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            private_key, public_key = rsa_generate_key_pair()
            data = {'public_key': public_key}
            headers = {'Authorization': f'Bearer {self.access_token}'}
            aes_key_response = requests.post('https://9b05-213-200-40-238.ngrok-free.app/generate_key', json=data, headers=headers)

            encrypted_aes_key = aes_key_response.json().get('encrypted_aes_key')
            aes_key = rsa_decrypt_text(private_key, encrypted_aes_key)

            with open(file_path, 'rb') as file:
                file_data = file.read()
            encrypted_file = BytesIO(aes_encrypt(file_data, aes_key))
            headers = {'Authorization': f'Bearer {self.access_token}'}
            with open(file_path, 'rb') as file:
                files = {'file': (file_path, encrypted_file)}
                response = requests.post('https://9b05-213-200-40-238.ngrok-free.app/upload', files=files,
                                         headers=headers
                                         )
            messagebox.showinfo("Обран завантажений", f"Файл {file_path} успішно завантажений!")
            self.close_files_window()
            self.open_files_window()


if __name__ == "__main__":
    root = tk.Tk()
    app = CloudStorageApp(root)
    root.mainloop()
