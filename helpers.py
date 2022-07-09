from functools import wraps
from flask import redirect, url_for, session, flash

# From flask decorator documentation
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' not in session:
            flash(f'You are not authorized to view that page without logging in, please login below.', 'danger')
            return redirect(url_for('userAuthRoutes.login'))
        return f(*args, **kwargs)
    return wrap