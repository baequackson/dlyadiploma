import requests
from rsa import *
from aes import *
from io import BytesIO


def confirm_email(url):

    code = url.split("?code=")[-1]
    data = {'code': code}

    response = requests.post(
        f'{base_url}/confirm_email',
        json=data
    )

    if response.status_code == 200:
        print('Email підтверджено!')
    else:
        print('Помилка підтвердження')


def upload_file(file_path, aes_key, access_token):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_file = BytesIO(aes_encrypt(file_data, aes_key))
    headers = {'Authorization': f'Bearer {access_token}'}
    with open(file_path, 'rb') as file:
        files = {'file': (file_path, encrypted_file)}
        response = requests.post(f'{base_url}/upload', files=files,
                                 headers=headers
                                 )


def download_file(file_id, access_token, public_key, private_key, code):
    data = {'public_key': public_key, 'code': code}

    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.post(f'{base_url}/download/{file_id}', headers=headers, json=data)
    if response.status_code == 200:
        encrypted_aes_key = response.headers.get('encrypted_aes_key')
        aes_key = rsa_decrypt_text(private_key, encrypted_aes_key)

        with open(f'downloaded_file_{file_id}', 'wb') as file:
            file.write(aes_decrypt(response.content, aes_key))
        print('File downloaded successfully.')
    else:
        print(response.status_code)


if __name__ == '__main__':
    base_url = 'http://127.0.0.1:5000'

    username = input("Username: ")
    password = input("Password: ")
    email = input("Email: ")

    # register_data = {'username': username, 'password': password, 'email': email}
    # register_response = requests.post(f'{base_url}/register', json=register_data)
    # if register_response.status_code != 201:
    #     print(register_response.json())
    # url = input('Введіть посилання підтвердження: ')

    # confirm_email(url)


    login_data = {'username': username, 'password': password}
    login_response = requests.post(f'{base_url}/login', json=login_data)
    print(login_response.text)
    access_token = login_response.json().get('access_token')

    private_key, public_key = rsa_generate_key_pair()
    data = {'public_key': public_key}
    headers = {'Authorization': f'Bearer {access_token}'}
    aes_key_response = requests.post(f'{base_url}/generate_key', json=data, headers=headers)
    if aes_key_response.status_code != 200:
        raise Exception

    encrypted_aes_key = aes_key_response.json().get('encrypted_aes_key')
    aes_key = rsa_decrypt_text(private_key, encrypted_aes_key)

    file_path = 'file2.txt'


    upload_file(file_path, aes_key, access_token)

    code = input()
    private_key, public_key = rsa_generate_key_pair()
    download_file('file2.txt', access_token, public_key, private_key, code)




# dekhtiar.8864774@stud.op.edu.ua