from flask import render_template, url_for, flash, redirect, request, Blueprint, session
from flask_login import login_user, current_user, logout_user, login_required
from chowkidar import oauth, get_admin
from chowkidar.models import User, db
from dotenv import load_dotenv
import os
from chowkidar.audits.routes import audit_list
from chowkidar import limiter, task_queue, mail
from chowkidar.utils.forms import ContactForm, WPSapiForm
from flask_mail import Message



utils = Blueprint('utils', __name__)
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



@utils.route('/')
def home():
    return render_template('utils/home.html')

@utils.route('/google/auth')
def auth():
    return google.authorize(callback=url_for('utils.google_auth', _external=True))




@utils.route('/google/auth/callback')
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
        return redirect(url_for('audits.audit_list'))
    else:
        flash('Login failed', 'danger')
        return redirect(url_for('utils.home'))




@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')




@utils.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    return current_user.email




@utils.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('utils.home'))



@utils.route('/contact', methods=['GET', 'POST'])
def contact():
    form = ContactForm()
    if request.method == 'POST':
        # Rate limit the POST requests
        @limiter.limit("1/minute")
        def send_message():
            if form.validate_on_submit():
                reciever = [os.environ['MAIL_USERNAME']]
                subject = f'{form.name.data} Wants to Connect'
                message = f'Name: {form.name.data} <p>Email: {form.email.data}</p> <p style="margin-top:2rem;">Message:</p><p style="margin-left:2rem;">{form.message.data}</p>'
                msg = Message(subject, sender=os.environ['MAIL_USERNAME'], recipients=reciever)
                msg.html = message
                try:
                    mail.send(msg)
                    flash('Your message has been successfully delivered.', 'success')
                except:
                    flash('Unable to deliver your message, please use an alternative method to communicate.', 'danger')
                return redirect(url_for('utils.home'))
            else:
                flash('The message could not be sent. Please verify your email address', 'danger')
        send_message()
    return render_template('utils/contact.html', title="Contact", form=form)
