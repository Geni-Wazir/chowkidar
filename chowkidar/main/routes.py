from flask import render_template, url_for, flash, redirect, request, Blueprint, current_app, session
from flask_login import login_user, current_user, logout_user, login_required
from chowkidar import oauth, get_admin
from chowkidar.models import User, db
from dotenv import load_dotenv
import os


users = Blueprint('users', __name__)
load_dotenv()
admins_list = get_admin()





google = oauth.remote_app(
    'google',
    consumer_key=os.environ.get('GOOGLE_CLIENT_ID'),
    consumer_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    request_token_params={
        'scope': 'openid email profile'
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)



@users.route('/')
def home():
    return render_template('home.html')

@users.route('/google/auth')
def auth():
    return google.authorize(callback=url_for('users.google_auth', _external=True))




@users.route('/google/auth/callback')
def google_auth():
    token = google.authorized_response()
    if token:
        session['google_token'] = (token['access_token'], '')
        user_info = google.get('userinfo')
        user = User.query.filter_by(email=user_info.data.get("email")).first()
        if not user:
            if user_info.data.get("email") in admins_list:
                user = User(email=user_info.data.get("email"), name=user_info.data.get("name"), admin=True)
            else:
                user = User(email=user_info.data.get("email"), name=user_info.data.get("name"))
            db.session.add(user)
            db.session.commit()
        
        login_user(user)
        return redirect(url_for('users.profile'))
    else:
        flash('Login failed', 'danger')
        return redirect(url_for('users.home'))




@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')


@users.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    return current_user.email


