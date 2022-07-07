from flask import render_template
import os, jwt
import requests
from time import time
from flask_mysqldb import MySQL
mysql = MySQL()

# Following Mailgun's standard api email format
def send_simple_message(subject, username, email, token, html, url, api, address):
    return requests.post(
        url,
        auth=("api", api),
        data={"from": address,
              "to": [email],
              "subject": subject,
              "html": render_template(html, username=username.capitalize(), token=token)})

# Generate reset token for forgotten passwords and registeration
def get_reset_token(user, expires=5000):
    return jwt.encode({'reset_password': user, 'exp': time() + expires}, key=str(os.environ.get('SECRET_KEY')), algorithm="HS256")

# Verify reset token from user clicking link in email
def verify_reset_token(token):
    try:
        username = jwt.decode(token, key=str(os.environ.get('SECRET_KEY')), algorithms="HS256")['reset_password']
    except Exception as e:
        print(e)
        print('token has expired')
        return None
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM users WHERE username = %s', [username])
    user = cur.fetchone()
    cur.close()
    return user
