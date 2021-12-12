from flask import Flask, render_template, redirect, flash, url_for, session, request, jsonify
from flask_mysqldb import MySQL
from flask_mail import Mail
from datetime import datetime
from passlib.hash import sha256_crypt
from helpers import login_required
from time import time
import jwt, os
from dotenv import load_dotenv
import requests

load_dotenv()

app = Flask(__name__)
mail = Mail(app)

app.config['MYSQL_HOST'] = os.environ.get('MySQL_HOST')
app.config['MYSQL_USER'] = os.environ.get("MySQL_USER")
app.config['MYSQL_PASSWORD'] = os.environ.get("MySQL_PASSWORD")
app.config['MYSQL_DB'] = 'heroku_7e98696366a4e2e'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

app.secret_key = 'super secret key'
app.config['SESSION_TYPE'] = 'filesystem'


mail = Mail(app)
mysql = MySQL(app)


# Welcome page
@app.route('/')
def welcome():
    return render_template('welcome.html')

# About
@app.route('/about')
def about():
    return render_template('about.html')

def send_simple_message(subject, username, email, token, html, url, api, address):
    return requests.post(
        url,
        auth=("api", api),
        data={"from": address,
              "to": [email],
              "subject": subject,
              "html": render_template(html, username=username.capitalize(), token=token)})

# Check email availability
@app.route('/check_email/<email>', methods=['POST'])
def check_email(email):
    if email != "False":
        input = str(email)
    else:
        input = str(request.form['input'])
    
    # Create cursor for database
    cur = mysql.connection.cursor()

    # Check if username entered in form matches anything in database
    user_found = cur.execute('SELECT * FROM users WHERE email = %s', [input])
    
    # To differentiate between a user editing his profile and someone registering a new profile
    if "logged_in" not in session:
        # Close the connection
        cur.close()

        if user_found != 0:
            result = 1
        else:
            result = 0
        return str(result)
    else:
        profile = cur.fetchone()
        # Check if a username is found and isn't the current users username
        if user_found != 0  and profile['username'] != session['username']:
            result = 1
        else:
            result = 0
        cur.close()
        return str(result)

# Check username availability
@app.route('/verify_username/<username>', methods=['POST'])
def verify_username(username):
    if username != "False":
        input = str(username)
    else:
        input = str(request.form['input'])

    # Create cursor for database
    cur = mysql.connection.cursor()
    input_un_capitalize = input[0].lower() + input[1:]
    input_capitalize = input.capitalize()

    # Check if username entered in form matches anything in database
    user_found = cur.execute('SELECT * FROM users WHERE username = %s or username = %s or username = %s', [input, input_capitalize, input_un_capitalize])

    # To differentiate between a user editing his profile and someone registering a new profile
    if "logged_in" not in session:
        # Close the connection
        cur.close()

        if user_found != 0:
            result = 1
        else:
            result = 0
    
        return str(result)
    else:
        profile = cur.fetchone()
        if user_found != 0  and profile['username'] == session['username']:
            result = 0
        elif user_found != 0  and profile['username'] != session['username']:
            result = 1
        else:
            result=0
        cur.close()
        return str(result)

# Register user
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        # Gather user form data
        name = request.form['name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm']
        encrypt_password = sha256_crypt.encrypt(str(password))
        dToday = datetime.now(tz=None).date()
        
        # Make sure form data is acceptable

        # Make sure no blank fields
        if not name or not email or not username or not password:
            message = "Registration fields cannot be blank"
            return render_template('register.html', message=message)
        
        # Make sure email is unique
        if check_email(email) != "0":
            message = f"Email \"{str(email)}\" is already being used."
            return render_template('register.html', message=message)

        # Make sure username is > 5
        if len(username) < 5:
            message = "Username must be 5 characters minimum."
            return render_template('register.html', message=message)
        
        # Make sure username is unique
        if verify_username(username) == "1":
            message = f"Username \"{str(username)}\" already taken"
            return render_template('register.html', message=message)

        # Make sure password > 5 characters
        if len(password) < 5:
            message = "Password must be 5 characters minimum"
            return render_template('register.html', message=message)

        if password != confirm_password:
            message = "The two password fields must be identical"
            return render_template('register.html', message=message)
        


        # Create cursor for database
        curr = mysql.connection.cursor()

        # Execute the insertion of the new user data
        curr.execute("INSERT INTO users (username, name, email, password, create_time) VALUES (%s, %s, %s, %s, %s)", (username, name, email, encrypt_password, dToday))

        # Commit data to db
        mysql.connection.commit()

        # Close connection
        curr.close()

        # Generate unique token for user
        token = get_reset_token(username)

        # Generate and send email through mailgun
        send_simple_message("FridgeMate Registration Confirmation", username.capitalize(), str(email), token, "email.html", os.environ.get("API_BASE_URL"), os.environ.get("MAIL_API_KEY"),  os.environ.get("MAIL_ADDRESS"))

        flash(f'You are now registered as a new user {username}, confirmation email has been sent', 'success')
        return render_template('login.html')
    else:
        return render_template('register.html')

@app.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):

    # Obtain username from token
    user = verify_reset_token(token)
    if user == None:
        flash('The link has expired, you may send another confirmation link below', 'danger')
        return redirect(url_for('resendConfirmation'))
    username = user['username']

    # Initialize a cursor to verify account
    cur = mysql.connection.cursor()
    cur.execute('UPDATE users SET verified = %s WHERE username = %s', ['yes', username])
    mysql.connection.commit()
    cur.close()

    flash('Account verified', 'success')
    return redirect(url_for('login'))

@app.route('/resendConfirmation', methods=['POST', 'GET'])
def resendConfirmation():
    if request.method == 'POST':

        # Verify email was entered correctly
        email = str(request.form['email'])
        if not email:
            error = 'Email field cannot be blank'
            return render_template('resendConfirmation.html', error=error)
        
        # Verify email has been registered in database
        cur = mysql.connection.cursor()
        found = cur.execute('SELECT * FROM users WHERE email = %s', [email])
        if found == 0:
            error='Email isn\t registered to an account (Go to \'Menu\'->\'Register\')'
            return render_template('resendConfirmation.html', error=error)
        
        user = cur.fetchone()
        username = user['username']
        # Generate unique token for user
        token = get_reset_token(username)

        # Registration confirmation email
        send_simple_message('FridgeMate Registration Confirmation', username, email, token, 'email.html', os.environ.get("API_BASE_URL"), os.environ.get("MAIL_API_KEY"),  os.environ.get("MAIL_ADDRESS"))

        flash(f'A new confirmation email has been sent out to {email}', 'success')
        return redirect(url_for('login'))
    else:
        return render_template('resendConfirmation.html')

# Log-in
@app.route('/login', methods=['POST', 'GET'])
def login():

    if request.method == 'POST':

        # Get form data
        username = request.form['username']
        password_entered = request.form['password']

        #Before continuing, verify inputs aren't blank
        if not username:
            error = "Username cannot be left blank"
            return render_template('/login.html', error=error)
        
        if not password_entered:
            error = "Password field cannot be blank"
            return render_template('/login.html', error=error)

        # First letter isn't case sensitive
        username_un_capitalize = username[0].lower() + username[1:]

        # Create cursor for database
        cur = mysql.connection.cursor()

        # Verify that the username entered in the form exists in the database
        user_found = cur.execute('SELECT * FROM users WHERE username = %s OR username = %s OR username = %s', [username, username.capitalize(), username_un_capitalize])
        
        if user_found > 0:
            data = cur.fetchone()
            password = data['password']

            if data['verified'] == 'no':
                error = 'Account locked until email is verified.'
                return render_template('login.html', error=error)

            if sha256_crypt.verify(password_entered, password):
                session['logged_in'] = True
                session['id'] = data['id']
                session['username'] = data['username']
                flash(f'Welcome {username.capitalize()}', 'success')
                cur.close()
                return redirect(url_for('fridge_view'))
            else:
                cur.close()
                error = 'Incorrect password'
                return render_template('login.html', error=error)

        else:
            error = 'Username does not exist'
            return render_template('login.html', error=error)

    else:
        return render_template('login.html')

# Generate reset token
def get_reset_token(user, expires=5000):
    return jwt.encode({'reset_password': user, 'exp': time() + expires}, key=str(os.environ.get('SECRET_KEY')), algorithm="HS256")

# Verify reset token
def verify_reset_token(token):
    try:
        username = jwt.decode(token, key=str(os.environ.get('SECRET_KEY')), algorithms="HS256")['reset_password']
        print(username)
    except Exception as e:
        print(e)
        print('token has expired')
        return None
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM users WHERE username = %s', [username])
    user = cur.fetchone()
    cur.close()
    return user

# Forgot Password
@app.route('/forgotPass', methods=['POST', 'GET'])
def forgotPass():
    if request.method == 'POST':

        # Create variable for email
        email = request.form['email']

        # Verify email is actually associated with an account
        cur = mysql.connection.cursor()
        check = cur.execute('SELECT * FROM users WHERE email = %s', [email])
        if check < 1:
            cur.close()
            error = 'Email isn\'t associated with an account'
            return render_template('password_reset.html', error=error)
        else:
            profile = cur.fetchone()
            cur.close()

            username = profile['username']

            # Generate unique token for user
            token = get_reset_token(username)

            # Generate forgot password email
            send_simple_message("Password Reset Confirmation", username.capitalize(), str(email), token, "password_reset_email.html", os.environ.get("API_BASE_URL"), os.environ.get("MAIL_API_KEY"),  os.environ.get("MAIL_ADDRESS"))
            flash(f"Password reset link has been sent to {str(email)}", "success")
            return redirect(url_for('login'))

    else:
        return render_template('password_reset.html')

# Reset password
@app.route('/reset_password/<token>', methods=['POST', 'GET'])
def reset_password(token):
    if request.method == 'POST':
        user = verify_reset_token(token)
        username = user['username']
        newPass = request.form['newPass']
        confirmPass = request.form['confirmNewPass']

        if not newPass or not confirmPass:
            error='Password fields cannot be blank.'
            return render_template('password_change.html', error=error, token=token)
        
        if newPass != confirmPass:
            error = 'Password fields must match.'
            return render_template('password_change.html', error=error, token=token)

        password = sha256_crypt.encrypt(str(newPass))
        cur = mysql.connection.cursor()
        cur.execute('UPDATE users SET password = %s WHERE username = %s', [password, username])
        mysql.connection.commit()
        cur.close()
        flash('Password updated successfully', 'success')
        return render_template('login.html')
    else:
        user = verify_reset_token(token)
        if not user:
            flash('No user found')
            return redirect(url_for('login'))
        
        return render_template('password_change.html', token=token)

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
       
    # Make sure new password and conrimation match (this would happen if someone bypassed javascript controls)
    if newPassword != confirmNewPassword:
        modal=1
        error = "Passwords dont match lol, you know you're web programming don't you"
        cur.close()
        return render_template('profile.html', error=error, profile=user, modal=modal, oldPassword=oldPasswordEntered, newPassword=newPassword, confirmPassword=confirmNewPassword)

    # Need to confirm old password matches before this change can be applied  
    oldPassword = user['password']
    if sha256_crypt.verify(oldPasswordEntered, oldPassword):
        newPass = sha256_crypt.encrypt(str(newPassword))
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

# User dashboard
@app.route('/dashboard', methods=['POST', 'GET'])
@login_required
def dashboard():
    if request.method == 'POST':

        return render_template('dashboard.html')
    else:
        return render_template('dashboard.html')
    
def days_left(id):

    # Create local connection to db
    cur = mysql.connection.cursor()

    # Retrieve all the users products
    cur.execute("SELECT * FROM items WHERE user_id = %s", [id])

    userProducts = cur.fetchall()
    i = 1
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

            dToday = datetime.now(tz=None)
            dExp = datetime.strptime(dateExp, '%Y-%m-%d')

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

            tree = 1

            flash(f'{entry} was successfully added to your fridge!  {daysLeft} days left', 'success')
            return redirect(url_for('add_item', tree=tree))
        
        # Else if new entry submitted
        elif request.form['entryButton'] == 'new':

            # Copy users ID selection into entry variable
            entry = (request.form['newItem']).capitalize()
            user_id = session['id']
            dateExp = request.form['newEntryDate']

            dToday = datetime.now(tz=None)
            dExp = datetime.strptime(dateExp, '%Y-%m-%d')

            diff = dExp.date() - dToday.date()
            daysLeft = diff.days

            # Create cursor for database
            cur = mysql.connection.cursor()

            # Execute the insertion of the new user data into items table
            cur.execute("INSERT INTO items (user_id, item, expiry_date, days_left) VALUES (%s, %s, %s, %s)", (user_id, entry, dExp.date(), daysLeft))

            # Check if food name has been entered before or is already in database
            verify = cur.execute("SELECT foodname FROM foods WHERE foodname = %s", [entry])

            if verify < 1:
                # Execute the insertion of the new food data into foods table
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
            error = 'Something went wrong.. please try again.'
            return redirect(url_for('add_item'))

    # Request GET method    
    else:
        
        # Hold user ID in variable
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
            
            # Check if modal should be in visible state
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

@app.route('/autocomplete', methods=['GET'])
def autocomplete():

    search = request.args.get('input')

    # Create cursor for database
    curr = mysql.connection.cursor()

    # Find matching results in the foodname table
    matches = curr.execute("SELECT foodname FROM foods WHERE foodname LIKE %s LIMIT 5", ['%' + search + '%'])
    if matches < 1:
        # Close connection
        curr.close()
        results = []
        return jsonify(results)
    else:
        results = []
        totalMatches = curr.fetchall()

        for match in totalMatches:
            results.append(match['foodname'])
        
        # Close connection
        curr.close()
        return jsonify(results)

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