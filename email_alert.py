
from flask import Flask, app, render_template
from dotenv import load_dotenv, find_dotenv
import os
import requests
from datetime import datetime
import mysql.connector

app = Flask(__name__)
load_dotenv()


# Had to copy these functions because mysql cursor issues

# Update days left column for each item a user has in their fridge
def days_left(id):

    # Create local connection to db
    cur = conn.cursor(dictionary=True)

    # Retrieve all the users products
    cur.execute("SELECT * FROM items WHERE user_id = %s", [id])

    # Store all user products in list of dictionaries
    userProducts = cur.fetchall()

    # update days left for each product
    for product in userProducts:
        dateExp = product['expiry_date']
        dToday = datetime.now(tz=None)
        daysLeft = (dateExp - dToday.date()).days
        cur.execute("UPDATE items SET days_left = %s WHERE item_id = %s AND deleted = %s", (daysLeft, product['item_id'], "no"))
    
    # Commit queries
    conn.commit()
    cur.close()

# Update days left for all users
def daysLeftAll():

    # Create cursor
    cur = conn.cursor(dictionary=True)

    # Select all user id's
    cur.execute('SELECT id FROM users')

    users = cur.fetchall()
    cur.close()

    for user in users:
        days_left(user["id"])

def send_simple_message(subject, username, email, items, html):
    return requests.post(
        os.environ.get("API_BASE_URL"),
        auth=("api", os.environ.get("MAIL_API_KEY")),
        data={"from": "FridgeMate " + os.environ.get("MAIL_ADDRESS"),
              "to": [email],
              "subject": subject,
              "html": render_template(html, username=username, items=items)})


# Determine which users will need alert emails
def sendEmailAlerts():
    # Create cursor
    cur = conn.cursor(dictionary=True)

    # Create list of dictionaries containing all users
    cur.execute('SELECT * FROM users')
    users = cur.fetchall()
    dToday = datetime.now(tz=None)
    for user in users:

        # Check if its the users first email alert
        if user['date_last_alert'] == None:
            # Guarantee email sent out for first time users
            dateLastAlert = datetime(2021, 11, 11).date()
        else:
            dateLastAlert = user['date_last_alert']
        
        # Create list to store each users items
        alertItems = []

        # Determine if the min days between alerts has been reached
        daysSinceLastAlert = (dToday.date() - dateLastAlert).days

        if daysSinceLastAlert >= user['min_days_between_alerts']:

            # Gather all user items in fridge that aren't deleted
            cur.execute("SELECT * FROM items WHERE user_id = %s AND deleted = %s", [user['id'], "no"])
            userItems = cur.fetchall()

            # Generate list of items where days_left within users specified alert threshold
            for item in userItems:
                if item['days_left'] <= user['alert_threshold']:
                    alertItems.append(item)
            
            # Make sure there's actually items in the list before sending email
            if len(alertItems) > 0:
                alertItems.sort(key=lambda x: x['days_left'])
                cur.execute("UPDATE users SET date_last_alert = %s where id = %s", [dToday.date(), user['id']])
                send_simple_message("FridgeMate Expiry Notification", user['username'], user['email'], alertItems, "alert_email.html")
    conn.commit()
    cur.close()
    

# Main program to be run daily #
################################  

#establishing the connection
conn = mysql.connector.connect(user=os.environ.get("MySQL_USER"), password=os.environ.get("MySQL_PASSWORD"), host=os.environ.get('MySQL_HOST'), database='heroku_7e98696366a4e2e')

# Update all items days_left column
daysLeftAll()

# Send out emails if there's items within the users specified alert threshold
with app.app_context():
    sendEmailAlerts()

# Close the database connection
conn.close()