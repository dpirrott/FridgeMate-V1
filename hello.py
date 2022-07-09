from flask import Flask, render_template, redirect, flash, url_for, session, request, jsonify

from flask_mail import Mail
from datetime import datetime
from passlib.hash import sha256_crypt
from helpers import login_required
from user_auth.routes import userAuth
from flask_mysqldb import MySQL
import os
from dotenv import load_dotenv


load_dotenv()

app = Flask(__name__)
mail = Mail(app)
mysql = MySQL()
mysql.init_app(app)

# Link MySQL database to app
app.config['MYSQL_HOST'] = os.environ.get('MySQL_HOST')
app.config['MYSQL_USER'] = os.environ.get("MySQL_USER")
app.config['MYSQL_PASSWORD'] = os.environ.get("MySQL_PASSWORD")
app.config['MYSQL_DB'] = 'heroku_7e98696366a4e2e'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

app.secret_key = 'super secret key'
app.config['SESSION_TYPE'] = 'filesystem'




app.register_blueprint(userAuth)

# Welcome page
@app.route('/')
def welcome():
    return render_template('welcome.html')

# User profile
@app.route('/profile', methods=['POST', 'GET'])
@login_required
def profile():

    user_id = session['id']

    # Create cursor for database
    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users WHERE id = %s", [user_id])
    profile = cur.fetchone()
    cur.close()
    return render_template('profile.html', profile=profile)

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

# Edit profile
@app.route('/edit_profile', methods=['POST'])
@login_required
def edit_profile():

    # Convert form data to easy to read variables
    name = request.form['name']
    username = request.form['username']
    email = request.form['email']
    oldUsername = session['username']
    user_id = session['id']
    alert_threshold = int(request.form['notification'])
    alert_frequency = int(request.form['frequency'])

    # Establish connection to database via cursor
    cur = mysql.connection.cursor()

    # Make sure data isn't left blank
    if not name:
        error = "Name field cannot be blank"
        cur.execute("SELECT * FROM users WHERE username = %s", [oldUsername])
        profile = cur.fetchone()
        cur.close()
        modal = 1
        return render_template('profile.html', profile=profile, modal2=modal, error=error)

    if not username:
        error = "Username field cannot be blank"
        cur.execute("SELECT * FROM users WHERE username = %s", [oldUsername])
        profile = cur.fetchone()
        cur.close()
        modal = 1
        return render_template('profile.html', profile=profile, modal2=modal, error=error)

    if not email:
        error = "Email field cannot be blank"
        cur.execute("SELECT * FROM users WHERE username = %s", [oldUsername])
        profile = cur.fetchone()
        cur.close()
        modal = 1
        return render_template('profile.html', profile=profile, modal2=modal, error=error)

    # Make sure somebody didn't overide alert settings outside their limits
    if alert_threshold > 7 or alert_threshold < 0:
        error="Notification trigger out of range (Must be between 0 - 7)"
        cur.execute("SELECT * FROM users WHERE username = %s", [oldUsername])
        profile = cur.fetchone()
        cur.close()
        modal = 1
        return render_template('profile.html', profile=profile, modal2=modal, error=error)

    if alert_frequency > 7 or alert_frequency < 1:
        error="Notification frequency out of range (Must be between 1 - 7)"
        cur.execute("SELECT * FROM users WHERE username = %s", [oldUsername])
        profile = cur.fetchone()
        cur.close()
        modal = 1
        return render_template('profile.html', profile=profile, modal2=modal, error=error)

    # Make sure email isn't already in use
    if checkEmail(email, oldUsername) > 0:
        error = f"Email {str(email)} is taken"
        cur.execute("SELECT * FROM users WHERE username = %s", [oldUsername])
        profile = cur.fetchone()
        cur.close()
        modal = 1
        return render_template('profile.html', profile=profile, modal2=modal, error=error)

    # Check lower case first letter just in case the username is capitalized in the input
    lower = username[0].lower() + username[1:]

    # Verify new username is actually available (if someone bypasses JS safeguard)
    taken = cur.execute('SELECT * FROM users WHERE username = %s or username = %s or username = %s', [username, username.capitalize(), lower])

    # Check if desired username is found in system, and isn't the current users username
    if taken > 0 and username != oldUsername:
        cur.execute('SELECT * FROM users WHERE username = %s', [oldUsername])
        profile = cur.fetchone()
        cur.close()
        modal = 1
        error = f'The username {username} is already taken.'
        return render_template('profile.html', profile=profile, modal2=modal, error=error)
    else:
        cur.execute('UPDATE users SET name = %s, username = %s, email = %s, alert_threshold = %s, min_days_between_alerts = %s WHERE id = %s', [name, username, email, alert_threshold, alert_frequency, user_id])
        session['username'] = username
        mysql.connection.commit()
        cur.close()
        flash("Profile information successfully updated", "success")
        return redirect(url_for('profile'))

# Change Password
@app.route('/changePassword', methods=['POST'])
@login_required
def changePassword():

    # Put form data into easy to read variables
    oldPasswordEntered = request.form['oldPass']
    newPassword = request.form['newPass']
    confirmNewPassword = request.form['confirmNewPass']
    username = session['username']

    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM users WHERE username = %s', [username])
    user = cur.fetchone()

    # Make sure old password field isn't blank
    if not oldPasswordEntered:
        modal = 1
        error = "Old password cannot be blank"
        cur.close()
        return render_template('profile.html', error=error, profile=user, modal=modal, oldPassword=oldPasswordEntered, newPassword=newPassword, confirmPassword=confirmNewPassword)

    # Make sure new password and confirmation match (the only time they wouldnt match is if someone bypassed javascript controls)
    if newPassword != confirmNewPassword:
        modal=1
        error = "Passwords dont match lol, you know you're web programming don't you"
        cur.close()
        return render_template('profile.html', error=error, profile=user, modal=modal, oldPassword=oldPasswordEntered, newPassword=newPassword, confirmPassword=confirmNewPassword)

    # Need to confirm old password matches before this change can be applied
    oldPassword = user['password']
    if sha256_crypt.verify(oldPasswordEntered, oldPassword):
        newPass = sha256_crypt.hash(str(newPassword))
        cur.execute('UPDATE users SET password = %s WHERE username = %s', [newPass, username])

        # Commit data to db
        mysql.connection.commit()

        # Close cursor connection to db
        cur.close()

        flash('Password changed successfully', 'success')
        return render_template('login.html')

    else:
        error = "Old Password is incorrect"
        cur.close()
        modal=1
        return render_template('profile.html', error=error, profile=user, modal=modal, oldPassword=oldPasswordEntered, newPassword=newPassword, confirmPassword=confirmNewPassword)

# Log-out
@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect('login')

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

# Add new item
@app.route('/add_item/<tree>', methods=['POST', 'GET'])
@login_required
def add_item(tree):

    # Request POST method
    if request.method == 'POST':

        # Check which hidden field value was selected
        # If previous entry submitted
        if request.form['entryButton'] == 'previous':

            # Copy users ID selection into entry variable
            entry = request.form['previousEntry']
            user_id = session['id']
            dateExp = request.form['previousEntryDate']

            # Verify a previous entry is selected and date is filled in
            if not dateExp:
                flash('Expiry needs to be filled in', 'danger')
                return redirect(url_for('add_item'))

            if entry == 'nothing':
                flash('Previous item must be selected', 'danger')
                return redirect(url_for('add_item'))

            # Put todays date and selected expiry date into datatime objects
            dToday = datetime.now(tz=None)
            dExp = datetime.strptime(dateExp, '%Y-%m-%d')

            # Calculate days left by subtracting difference between expiry date and current date, then convert to days
            diff = dExp.date() - dToday.date()
            daysLeft = diff.days

            # Create cursor for database
            cur = mysql.connection.cursor()

            # Execute the insertion of the new user data
            cur.execute("INSERT INTO items (user_id, item, expiry_date, days_left) VALUES (%s, %s, %s, %s)", (user_id, entry, dExp.date(), daysLeft))

            # Gather all items the user has entered into fridge
            cur.execute("SELECT DISTINCT item FROM items WHERE user_id = %s", [user_id])
            previousItems = cur.fetchall()

            # Commit data to db
            mysql.connection.commit()

            # Close connection
            cur.close()

            # flag for triggering a modal
            tree = 1

            flash(f'{entry} was successfully added to your fridge!  {daysLeft} days left', 'success')
            return redirect(url_for('add_item', tree=tree))

        # Else if new entry submitted
        elif request.form['entryButton'] == 'new':

            # Copy users ID selection into entry variable
            entry = (request.form['newItem']).capitalize()
            user_id = session['id']
            dateExp = request.form['newEntryDate']

            # Put todays date and selected expiry date into datatime objects
            dToday = datetime.now(tz=None)
            dExp = datetime.strptime(dateExp, '%Y-%m-%d')

            # Calculate days left by subtracting difference between expiry date and current date, then convert to days
            diff = dExp.date() - dToday.date()
            daysLeft = diff.days

            # Create cursor for database
            cur = mysql.connection.cursor()

            # Execute the insertion of the new user data into items table
            cur.execute("INSERT INTO items (user_id, item, expiry_date, days_left) VALUES (%s, %s, %s, %s)", (user_id, entry, dExp.date(), daysLeft))

            # Check if food name has been entered in before or is already in database
            verify = cur.execute("SELECT foodname FROM foods WHERE foodname = %s", [entry])
            if verify < 1:
                # Execute the insertion of the new food data into foods table for improving autocomplete list
                cur.execute("INSERT INTO foods (foodname) VALUES (%s)", [entry.capitalize()])

            # Gather all items the user has entered into fridge
            cur.execute("SELECT DISTINCT item FROM items WHERE user_id = %s", [user_id])
            previousItems = cur.fetchall()

            # Commit data to db
            mysql.connection.commit()

            # Close connection
            cur.close()

            tree = 1

            flash(f'{entry} was successfully added to your fridge!  {daysLeft} days left', 'success')
            return redirect(url_for('add_item', tree=tree))

        else:
            flash('Something went wrong.. please try again.','danger')
            return redirect(url_for('add_item'))

    # Request GET method
    else:

        # Store user ID in variable
        user_id = session['id']

        # Create cursor for database
        cur = mysql.connection.cursor()

        # Gather all items the user has entered into fridge
        resultCount = cur.execute("SELECT DISTINCT item FROM items WHERE user_id = %s", [user_id])

        if resultCount < 1:
            tree = 0
            return render_template('add_item.html', tree=tree)
        else:

            # Store users previous items in a dictionary
            previousItems = cur.fetchall()

            # Close connection
            cur.close()

            # Check if modal should be in visible state, tree is a flag for triggering a modal
            if tree == "1":
                tree = 1 # Convert str to int
                return render_template('add_item.html', previousItems=previousItems, tree=tree)
            else:
                tree = 0
                return render_template('add_item.html', previousItems=previousItems, tree=tree)

# Fridge view
@app.route('/fridge_view')
@login_required
def fridge_view():

    # Need user id for gathering inventory of products
    user_id = session['id']

    # Update days left column of items table
    days_left(user_id)

    # Create cursor for database
    cur = mysql.connection.cursor()

    # Gather users personal inventory
    cur.execute("SELECT * FROM items WHERE user_id = %s ORDER BY days_left ASC", [user_id])
    userProducts = cur.fetchall()

    # Close connection to db
    cur.close()

    return render_template('fridge_view.html', userProducts=userProducts)

# Added autocomplete functionality for the add new item text input
@app.route('/autocomplete', methods=['GET'])
def autocomplete():

    # Users word in progress for autocomplete list
    search = request.args.get('input')

    # Create cursor for database
    curr = mysql.connection.cursor()

    # Find matching results in the foodname table
    matches = curr.execute("SELECT foodname FROM foods WHERE foodname LIKE %s LIMIT 5", ['%' + search + '%'])
    if matches < 1:
        # Close connection, potentially a new item being entered
        curr.close()
        results = []
        return jsonify(results)
    else:
        results = []
        totalMatches = curr.fetchall()

        # Store all potential search results in results
        for match in totalMatches:
            results.append(match['foodname'])

        # Close connection and send jsonified list of results
        curr.close()
        return jsonify(results)

# Ajax post request for deleting entries on the fridgeview page
@app.route('/deleteEntries', methods=['POST'])
def deleteEntries():
    data = request.get_json()
    toDeleteEntries = data['entries']
    message="It works!"

    # Create cursor for database
    cur = mysql.connection.cursor()

    # Queries for deleting each of the entries to be deleted
    for entry in toDeleteEntries:
        cur.execute("UPDATE items SET deleted = %s WHERE item_id = %s", ["yes", str(entry)])

    # Commit deletion queries
    mysql.connection.commit()

    # Close the connection
    cur.close()

    return message



if __name__ == '__main__':
    app.run(debug=True)
    app.run(host="0.0.0.0")