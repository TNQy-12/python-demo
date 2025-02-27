import smtplib
from email.mime.text import MIMEText

def send_alert(alerts, sender, receiver, password):
    if not alerts:
        return

    msg = MIMEText("\n".join(alerts))
    msg['Subject'] = 'Cảnh báo tấn công hệ thống'
    msg['From'] = sender
    msg['To'] = receiver

    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, receiver, msg.as_string())
    print("Đã gửi email cảnh báo!")