import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


def send_confirmation_email(email, username, code):
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = 'cba19787@gmail.com'
    smtp_password = 'vkdw yxcv txkh vufn'

    sender_email = smtp_username
    receiver_email = email

    message = MIMEMultipart("alternative")
    message["Subject"] = "Підтвердження реєстрації"
    message["From"] = sender_email
    message["To"] = receiver_email

    text = f"""\
    Вітаємо, {username}!

    Дякуємо за реєстрацію в нашому хмарному сховищі.

    Щоб завершити реєстрацію, будь ласка, перейдіть за наступним посиланням:

    http://127.0.0.1:5000/confirm_email?code={code}

    Якщо ви не можете перейти за посиланням, скопіюйте його та вставте в адресний рядок браузера.

    Посилання буде дійсним протягом 24 годин.

    Із повагою,
    Адміністрація хмарного сховища
    """

    part = MIMEText(text, "plain")
    message.attach(part)

    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_username, smtp_password)
    server.sendmail(sender_email, receiver_email, message.as_string())
    server.quit()
