from flask import requests, render_template

# Following Mailgun's standard api email format
def send_simple_message(subject, username, email, token, html, url, api, address):
    return requests.post(
        url,
        auth=("api", api),
        data={"from": address,
              "to": [email],
              "subject": subject,
              "html": render_template(html, username=username.capitalize(), token=token)})

