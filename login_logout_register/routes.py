from flask import Blueprint, request, render_template, flash
from datetime import datetime
from hello import mysql

userAuth = Blueprint('userAuth', __name__)

# Register user
@userAuth.route('/register', methods=['GET', 'POST'])
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

# Check email availability
@userAuth.route('/check_email/<email>', methods=['POST'])
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
@userAuth.route('/verify_username/<username>', methods=['POST'])
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
