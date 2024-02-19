import tkinter as tk
from tkinter import messagebox, filedialog
import requests


class CloudStorageApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Облачное Хранилище")

        self.register_button = tk.Button(root, text="Зарегистрироваться", command=self.open_register_window)
        self.register_button.pack(pady=10)

        self.login_button = tk.Button(root, text="Войти", command=self.open_login_window)
        self.login_button.pack(pady=10)

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
            self.open_confirmation_window(email)
        else:
            messagebox.showerror("Ошибка", "Не удалось зарегистрироваться.")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        data = {'username': username, 'password': password}
        response = requests.post('http://127.0.0.1:5000/login', json=data)

        if response.status_code == 200:
            messagebox.showinfo("Успех", "Вход выполнен успешно!")
            self.close_login_window()
            self.open_files_window()  # Открываем окно со списком файлов после успешного входа
        else:
            messagebox.showerror("Ошибка", "Неверное имя пользователя или пароль.")

    def open_confirmation_window(self, email):
        self.confirmation_window = tk.Toplevel()

        self.confirmation_window.title("Подтверждение Email")

        self.code_label = tk.Label(self.confirmation_window, text="Введите код подтверждения из письма:")
        self.code_label.grid(row=0, column=0, sticky="e")
        self.code_entry = tk.Entry(self.confirmation_window)
        self.code_entry.grid(row=0, column=1)

        self.confirm_button = tk.Button(self.confirmation_window, text="Подтвердить", command=lambda: self.confirm_email(email))
        self.confirm_button.grid(row=1, column=0, columnspan=2, pady=10)

        self.back_button = tk.Button(self.confirmation_window, text="Назад", command=self.confirmation_window.destroy)
        self.back_button.grid(row=2, column=0, columnspan=2, pady=10)

    def confirm_email(self, email):
        code = self.code_entry.get()
        data = {'code': code}
        response = requests.post('http://127.0.0.1:5000/confirm_email', json=data)

        if response.status_code == 200:
            messagebox.showinfo("Успех", "Email подтвержден успешно!")
            self.confirmation_window.destroy()
        else:
            messagebox.showerror("Ошибка", "Ошибка подтверждения Email.")

    def open_files_window(self):
        self.files_window = tk.Toplevel()
        self.files_window.title("Список файлов")

        # Получение списка файлов пользователя с сервера
        username = self.username_entry.get()  # Получаем имя пользователя
        response = requests.get(f'http://127.0.0.1:5000/files/{username}')  # Запрос на получение списка файлов

        if response.status_code == 200:
            files = response.json().get('files')  # Получаем список файлов
            if files:
                # Отображаем список файлов
                self.files_label = tk.Label(self.files_window, text="Список загруженных файлов:")
                self.files_label.pack()

                for file in files:
                    file_name = file.split('_')[-1]  # Получаем имя файла из пути
                    file_button = tk.Button(self.files_window, text=file_name)
                    file_button.pack(pady=5)
            else:
                no_files_label = tk.Label(self.files_window, text="У вас пока нет загруженных файлов")
                no_files_label.pack(pady=10)

        else:
            messagebox.showerror("Ошибка", "Не удалось получить список файлов.")

        # Кнопка для выбора файла
        select_file_button = tk.Button(self.files_window, text="Выбрать файл", command=self.open_file_selection_window)
        select_file_button.pack(pady=10)

    def open_file_selection_window(self):
        file_path = filedialog.askopenfilename()  # Диалоговое окно для выбора файла
        if file_path:
            # Выбор файла прошел успешно, можно его загрузить на сервер
            messagebox.showinfo("Выбран файл", f"Выбран файл: {file_path}")
            # Здесь можно добавить код для загрузки выбранного файла на сервер

if __name__ == "__main__":
    root = tk.Tk()
    app = CloudStorageApp(root)
    root.mainloop()
