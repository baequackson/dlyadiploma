import requests
from rsa import *


# Замените URL на ваш адрес локального сервера


def confirm_email(url):
    # Получите код подтверждения из ссылки
    code = url.split("?code=")[-1]
    data = {'code': code}
    # Подтвердите адрес электронной почты
    response = requests.post(
        f'{base_url}/confirm_email',
        json=data
    )

    # Обработайте ответ
    if response.status_code == 200:
        print('Email подтвержден')
    else:
        print('Ошибка подтверждения')


def upload_file(file_path, encrypted_aes_key, access_token):
    # Пример загрузки файла на сервер
    headers = {'Authorization': f'Bearer {access_token}'}
    with open(file_path, 'rb') as file:
        files = {'file': file}
        data = {'encrypted_aes_key': encrypted_aes_key}
        response = requests.post(f'{base_url}/upload', files=files, data=data, headers=headers)
    print(response.text)


def download_file(file_id, access_token):
    # Пример скачивания файла с сервера
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(f'{base_url}/download/{file_id}', headers=headers)
    with open(f'downloaded_file_{file_id}.txt', 'wb') as file:
        file.write(response.content)
    print('File downloaded successfully.')


if __name__ == '__main__':
    base_url = 'http://127.0.0.1:5000'

    username = input("Username: ")
    password = input("Password: ")
    email = input("Email: ")

    # Регистрация нового пользователя
    register_data = {'username': username, 'password': password, 'email': email}
    register_response = requests.post(f'{base_url}/register', json=register_data)
    if register_response.status_code != 201:
        print(register_response.json())
    url = input('Введите ссылку подтверждения: ')

    confirm_email(url)

    # Вход пользователя
    login_data = {'username': username, 'password': password}
    login_response = requests.post(f'{base_url}/login', json=login_data)
    print(login_response.text)
    access_token = login_response.json().get('access_token')

    private_key, public_key = rsa_generate_key_pair()
    data = {'public_key': public_key}

    aes_key_response = requests.post(f'{base_url}/generate_key', json=data)
    if aes_key_response.status_code != 200:
        raise Exception

    encrypted_aes_key = aes_key_response.json().get('encrypted_aes_key')
    aes_key = rsa_decrypt_text(private_key, encrypted_aes_key)

    # # Необходимо получить путь к файлу, который вы хотите загрузить
    # file_path = 'file.txt'
    #
    # # Необходимо получить токен доступа от сервера после аутентификации
    # access_token = 'your_access_token'
    #
    # # Загрузка файла на сервер
    # upload_file(file_path, encrypted_aes_key_hex, access_token)

# dekhtiar.8864774@stud.op.edu.ua
