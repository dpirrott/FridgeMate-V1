from datetime import datetime
from flask_mysqldb import MySQL

mysql = MySQL()

# Takes in an email address as a parameter and checks if it already exists in the database
def checkEmail(email, username):

    # Create cursor
    cur = mysql.connection.cursor()

    found = cur.execute('SELECT * FROM users WHERE email = %s', [email])
    if found == 0:
        return 0
    user = cur.fetchone()
    if  user['username'] == username:
        found = found - 1

    return found

# Calculate the days left on all products in a specific users fridge based on their user_id
def days_left(id):

    # Create local connection to db
    cur = mysql.connection.cursor()

    # Retrieve all the users products
    cur.execute("SELECT * FROM items WHERE user_id = %s", [id])

    userProducts = cur.fetchall()

    # update days left for each product
    for product in userProducts:
        dateExp = product['expiry_date']
        dToday = datetime.now(tz=None)
        daysLeft = (dateExp - dToday.date()).days
        cur.execute("UPDATE items SET days_left = %s WHERE item_id = %s AND deleted = %s", (daysLeft, product['item_id'], "no"))

    # Commit queries
    mysql.connection.commit()

    # Close connection
    cur.close()
