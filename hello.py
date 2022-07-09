from flask import Flask
from flask_mail import Mail
from user_auth_routes.routes import userAuthRoutes
from core_app_routes.routes import coreRoutes
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

# All routes related to core functionality of FridgeMate
app.register_blueprint(coreRoutes)

# All routes related to login, register, password changes, verify email/username
app.register_blueprint(userAuthRoutes)

if __name__ == '__main__':
    app.run(host="0.0.0.0")