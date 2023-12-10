import sys
import subprocess
from smtplib import SMTP_SSL
import toml
import pathlib
import datetime
import socket
import sendgrid
import os
from sendgrid.helpers.mail import *


def send_alert(cfg, errors):
    server = SMTP_SSL(cfg['otp']['email']['server'], 465)
    server.login(cfg['otp']['email']['account'],
                 cfg['otp']['email']['password'])
    from_account = cfg['otp']['email']['sender']
    to_accounts = cfg['alerts']['mail']
    msg = format_msg(from_account, to_accounts, errors)
    print(msg)
    server.sendmail(
        from_account,
        to_accounts,
        bytes(msg, 'utf-8')
    )
    server.quit()

def send_alert_new_api(cfg, errors):
    api_key = cfg['otp']['email_api']['password'].split(' ')[1]
    sg = sendgrid.SendGridAPIClient(api_key=api_key)
    from_email = Email(cfg['otp']['email_api']['sender'])
    to_email = To(cfg['alerts']['mail'])
    subject = "Dauth api alerts"
    content = Content("text/plain", "and easy to do anywhere, even with Python")
    mail = Mail(from_email, to_email, subject, content)
    response = sg.client.mail.send.post(request_body=mail.get())
    print(response.status_code)
    print(response.body)
    print(response.headers)

def format_msg(from_acc, to_accs, errs):
    return (
        "Subject: keysafe error alert\r\n"
        f"From: <{from_acc}>\r\n"
        f"To: <{','.join(to_accs)}>\r\n\r\n"
        f"{';'.join(errs)}"
    )


def append_path(log_path):
    working_dir = pathlib.Path(__file__).parent.resolve().parent.resolve()
    print(working_dir)
    return working_dir.joinpath(log_path)


def in_time_range(line):
    parts = line.split()
    if len(parts) > 6:
        log_time = line.split('|')[0].strip()
        try:
            c = datetime.datetime.now()
            a = datetime.datetime(c.year, c.month, c.day, c.hour, c.minute, 0)
            b = a - datetime.timedelta(minutes=5)
            log_time = datetime.datetime.fromisoformat(log_time)
            return log_time < a and log_time > b
        except Exception as err:
            print(err)
            return False
    print(parts)
    return False


def monitor_log_file(log_path):
    # looking for erros in the last n minutes
    log_path = append_path(log_path)
    print(log_path)
    errs = []
    with open(log_path, 'r') as f:
        for l in f.readlines():
            print('checking line:', l)
            if in_time_range(l):
                errs.append(l)
    return errs


def check_std_file_for_err(log_path):
    log_path = append_path(log_path)
    print(log_path)
    errs = []
    return errs


def monitor_app_port(api_conf):
    ip = api_conf['host']
    port = api_conf['port']
    result = subprocess.run(
        f"netstat -antp|grep {port}",
        shell=True,
        capture_output=True)
    content = result.stdout.decode('utf-8')
    for l in content.split('\n'):
        if 'LISTEN' in l and f'{ip}:{port}' == l.split()[3]:
            return []
    f_path = pathlib.Path(__file__).parent.resolve()
    hostname = socket.gethostname()
    return [f'{hostname}:{port} is not listening, {f_path} process is down.']


def monitor_status(conf):
    err1 = monitor_log_file('bin/logs/err.log')
    err3 = monitor_app_port(conf['api'])
    errs = err1 + err3
    if errs:
        send_alert(conf, errs)


def load_cfg(cfg_file):
    with open(cfg_file, 'r') as f:
        return toml.load(f)


if __name__ == '__main__':
    cfg = load_cfg(sys.argv[1])
    monitor_status(cfg)
