from flask import Blueprint, request, render_template, flash, redirect, url_for, session
from passlib.hash import sha256_crypt
from datetime import datetime
from helpers import login_required
from .auth_helpers import send_simple_message, get_reset_token, verify_reset_token, mysql
import os


userAuthRoutes = Blueprint('userAuthRoutes', __name__, url_prefix='/', template_folder='./templates')

# Register user
@userAuthRoutes.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':

        # Gather user form data
        name = request.form['name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm']
        encrypt_password = sha256_crypt.hash(str(password))
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

        # Make sure username is >= 5 characters
        if len(username) < 5:
            message = "Username must be 5 characters minimum."
            return render_template('register.html', message=message)

        # Make sure username is unique
        if verify_username(username) == "1":
            message = f"Username \"{str(username)}\" already taken"
            return render_template('register.html', message=message)

        # Make sure password >= 5 characters
        if len(password) < 5:
            message = "Password must be 5 characters minimum"
            return render_template('register.html', message=message)

        # Make sure password matches confirm password
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

# Log-in
@userAuthRoutes.route('/login', methods=['POST', 'GET'])
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

        # First letter isn't case sensitive so must check lowercase and uppercase first letter
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
                return redirect(url_for('coreRoutes.fridge_view'))
            else:
                cur.close()
                error = 'Incorrect password'
                return render_template('login.html', error=error)

        else:
            error = 'Username does not exist'
            return render_template('login.html', error=error)

    else:
        return render_template('login.html')

# Log-out
@userAuthRoutes.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect('login')


# Check email availability
@userAuthRoutes.route('/check_email/<email>', methods=['POST'])
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
@userAuthRoutes.route('/verify_username/<username>', methods=['POST'])
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

# Verify users email token is valid
@userAuthRoutes.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):

    # Obtain username from token
    user = verify_reset_token(token)

    # Ensure confirmation link isn't expired
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

# If user doesn't activate email token in time, send new confirmation email
@userAuthRoutes.route('/resendConfirmation', methods=['POST', 'GET'])
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

# Forgot Password
@userAuthRoutes.route('/forgotPass', methods=['POST', 'GET'])
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
@userAuthRoutes.route('/reset_password/<token>', methods=['POST', 'GET'])
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

        password = sha256_crypt.hash(str(newPass))
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

# Change Password
@userAuthRoutes.route('/changePassword', methods=['POST'])
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
