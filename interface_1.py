import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import requests

from dlyadiploma.aes import aes_encrypt, aes_decrypt
from rsa import rsa_generate_key_pair, rsa_decrypt_text
from io import BytesIO


class CloudStorageApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Облачное Хранилище")

        self.register_button = tk.Button(root, text="Зарегистрироваться", command=self.open_register_window)
        self.register_button.pack(pady=10)

        self.login_button = tk.Button(root, text="Войти", command=self.open_login_window)
        self.login_button.pack(pady=10)

        self.username = None
        self.access_token = None

    def open_register_window(self):
        self.root.withdraw()
        self.register_window = tk.Toplevel()

        self.register_window.protocol("WM_DELETE_WINDOW", self.close_register_window)

        self.register_window.title("Регистрация")

        self.username_label = tk.Label(self.register_window, text="Имя пользователя:")
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

        self.register_button = tk.Button(self.register_window, text="Зарегистрироваться", command=self.register)
        self.register_button.grid(row=3, column=0, columnspan=2, pady=10)

        self.back_button = tk.Button(self.register_window, text="Назад", command=self.close_register_window)
        self.back_button.grid(row=4, column=0, columnspan=2, pady=10)

    def open_login_window(self):
        self.root.withdraw()
        self.login_window = tk.Toplevel()

        self.login_window.protocol("WM_DELETE_WINDOW", self.close_login_window)

        self.login_window.title("Вход")

        self.username_label = tk.Label(self.login_window, text="Имя пользователя:")
        self.username_label.grid(row=0, column=0, sticky="e")
        self.username_entry = tk.Entry(self.login_window)
        self.username_entry.grid(row=0, column=1)

        self.password_label = tk.Label(self.login_window, text="Пароль:")
        self.password_label.grid(row=1, column=0, sticky="e")
        self.password_entry = tk.Entry(self.login_window, show="*")
        self.password_entry.grid(row=1, column=1)

        self.login_button = tk.Button(self.login_window, text="Войти", command=self.login)
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
        response = requests.post('http://127.0.0.1:5000/register', json=data)

        if response.status_code == 201:
            messagebox.showinfo("Успех", "Регистрация прошла успешно! Проверьте вашу почту для подтверждения.")
            self.close_register_window()
            # self.open_confirmation_window(email)
        else:
            messagebox.showerror("Ошибка", "Не удалось зарегистрироваться.")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        data = {'username': username, 'password': password}
        response = requests.post('http://127.0.0.1:5000/login', json=data)

        if response.status_code == 200:
            messagebox.showinfo("Успех", "Вход выполнен успешно!")
            self.username = username
            self.access_token = response.json().get('access_token')
            self.close_login_window()
            self.open_files_window()  # Открываем окно со списком файлов после успешного входа
        else:
            messagebox.showerror("Ошибка", "Неверное имя пользователя или пароль.")

    def open_files_window(self):
        self.root.withdraw()
        self.files_window = tk.Toplevel()
        self.files_window.title("Список файлов")

        # Получение списка файлов пользователя с сервера
        headers = {'Authorization': f'Bearer {self.access_token}'}
        response = requests.get(f'http://127.0.0.1:5000/files/{self.username}',
                                headers=headers)  # Запрос на получение списка файлов

        if response.status_code == 200:
            files = response.json().get('files')  # Получаем список файлов

            # Отображаем список файлов
            self.files_label = tk.Label(self.files_window, text="Список загруженных файлов:")
            self.files_label.pack()

            for file in files:
                file_name = file.split('_')[-1]  # Получаем имя файла из пути
                file_button = tk.Button(self.files_window, text=f"{file_name} ⬇️",
                                        command=lambda filename=file: self.request_code(filename))
                file_button.pack(pady=5)

        else:
            messagebox.showerror("Ошибка", "Ошибка сети.")

        select_file_button = tk.Button(self.files_window, text="Выбрать файл", command=self.open_file_selection_window)
        select_file_button.pack(pady=10)

    def close_files_window(self):
        self.files_window.destroy()
        self.root.deiconify()

    def request_code(self, filename):
        code = simpledialog.askstring("Ввод кода", f"Введите код для файла {filename}:")
        if code is not None:
            private_key, public_key = rsa_generate_key_pair()
            data = {'public_key': public_key, 'code': code}
            headers = {'Authorization': f'Bearer {self.access_token}'}

            response = requests.post(f'http://127.0.0.1:5000/download/{filename}', headers=headers, json=data)
            if response.status_code == 200:
                encrypted_aes_key = response.headers.get('encrypted_aes_key')
                aes_key = rsa_decrypt_text(private_key, encrypted_aes_key)

                with open(f'downloaded_file_{filename}', 'wb') as file:
                    file.write(aes_decrypt(response.content, aes_key))
                messagebox.showinfo("Успех", f"Файл {filename} успешно скачан!")
            else:
                messagebox.showerror("Ошибка", "Не удалось скачать файл.")

    def open_file_selection_window(self):
        file_path = filedialog.askopenfilename()  # Диалоговое окно для выбора файла
        if file_path:
            private_key, public_key = rsa_generate_key_pair()
            data = {'public_key': public_key}
            headers = {'Authorization': f'Bearer {self.access_token}'}
            aes_key_response = requests.post('http://127.0.0.1:5000/generate_key', json=data, headers=headers)

            encrypted_aes_key = aes_key_response.json().get('encrypted_aes_key')
            aes_key = rsa_decrypt_text(private_key, encrypted_aes_key)

            with open(file_path, 'rb') as file:
                file_data = file.read()
            encrypted_file = BytesIO(aes_encrypt(file_data, aes_key))
            headers = {'Authorization': f'Bearer {self.access_token}'}
            with open(file_path, 'rb') as file:
                files = {'file': (file_path, encrypted_file)}
                response = requests.post('http://127.0.0.1:5000/upload', files=files,
                                         headers=headers
                                         )
            messagebox.showinfo("Выбран загружен", f"Файл {file_path} успешно загружен!")
            self.close_files_window()
            self.open_files_window()


if __name__ == "__main__":
    root = tk.Tk()
    app = CloudStorageApp(root)
    root.mainloop()
