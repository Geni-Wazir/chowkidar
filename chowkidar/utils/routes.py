from flask import render_template, url_for, flash, redirect, request, Blueprint, session, make_response
from flask_login import login_user, current_user, logout_user, login_required
from chowkidar import oauth, get_admin
from chowkidar.models import User, Audit, VulnerabilityDiscovered, VulnerabilityTemplates, db
from dotenv import load_dotenv
import os
from chowkidar import limiter, task_queue, mail
from chowkidar.utils.forms import ContactForm, WPSapiForm
from flask_mail import Message
from chowkidar.utils.scheduler import generate_report



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
    if current_user.is_authenticated:
        return redirect(url_for('audits.audit_list'))
    return render_template('utils/home.html')

@utils.route('/google/auth')
def auth():
    return google.authorize(callback=url_for('utils.google_auth', _external=True))




@utils.route('/google/auth/callback')
def google_auth():
    token = google.authorized_response()
    print(admins_list)
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
    form = WPSapiForm()
    if form.validate_on_submit():
        current_user.wpscan_api = form.api_key.data
        db.session.commit()
        flash('API Key updated successfully', 'success')
        return redirect(url_for('utils.profile'))
    audit_count = Audit.query.filter_by(Auditor=current_user).count()
    audit_completed_count = Audit.query.filter_by(Auditor=current_user, status='finished').count()
    critical_count = VulnerabilityDiscovered.query \
                    .join(Audit, VulnerabilityDiscovered.audit_id == Audit.id) \
                    .join(User, Audit.user_id == User.id) \
                    .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
                    .filter(VulnerabilityTemplates.severity == "CRITICAL") \
                    .filter(User.id == current_user.id) \
                    .count()

    high_count = VulnerabilityDiscovered.query \
                    .join(Audit, VulnerabilityDiscovered.audit_id == Audit.id) \
                    .join(User, Audit.user_id == User.id) \
                    .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
                    .filter(VulnerabilityTemplates.severity == "HIGH") \
                    .filter(User.id == current_user.id) \
                    .count()

    medium_count = VulnerabilityDiscovered.query \
                    .join(Audit, VulnerabilityDiscovered.audit_id == Audit.id) \
                    .join(User, Audit.user_id == User.id) \
                    .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
                    .filter(VulnerabilityTemplates.severity == "MEDIUM") \
                    .filter(User.id == current_user.id) \
                    .count()

    low_count = VulnerabilityDiscovered.query \
                    .join(Audit, VulnerabilityDiscovered.audit_id == Audit.id) \
                    .join(User, Audit.user_id == User.id) \
                    .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
                    .filter(VulnerabilityTemplates.severity == "LOW") \
                    .filter(User.id == current_user.id) \
                    .count()

    info_count = VulnerabilityDiscovered.query \
                    .join(Audit, VulnerabilityDiscovered.audit_id == Audit.id) \
                    .join(User, Audit.user_id == User.id) \
                    .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
                    .filter(VulnerabilityTemplates.severity == "INFO") \
                    .filter(User.id == current_user.id) \
                    .count()
    if request.method == 'GET':
        form.api_key.data = current_user.wpscan_api
    
    return render_template('utils/profile.html', title="Profile", form=form,
                           audit_count=audit_count, 
                           audit_completed_count=audit_completed_count,
                           critical_count=critical_count,
                           high_count=high_count,
                           medium_count=medium_count,
                           low_count=low_count,
                           info_count=info_count
                           )




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





@utils.route('/report/<int:audit_id>')
@login_required
@limiter.limit("5/minute")
def report(audit_id):
    audit = Audit.query.filter_by(id=audit_id, Auditor=current_user).first()
    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('audits.audit_list'))
    
    vulnerabilities = vulnerabilities = VulnerabilityDiscovered.query \
    .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id)\
    .filter(VulnerabilityDiscovered.audit_id == audit.id) \
    .order_by(VulnerabilityTemplates.cvss.desc()).all()

    critical_count = VulnerabilityDiscovered.query \
                    .join(Audit, VulnerabilityDiscovered.audit_id == Audit.id) \
                    .join(User, Audit.user_id == User.id) \
                    .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
                    .filter(VulnerabilityTemplates.severity == "CRITICAL") \
                    .filter(Audit.id == audit.id) \
                    .count()
    high_count = VulnerabilityDiscovered.query \
                    .join(Audit, VulnerabilityDiscovered.audit_id == Audit.id) \
                    .join(User, Audit.user_id == User.id) \
                    .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
                    .filter(VulnerabilityTemplates.severity == "HIGH") \
                    .filter(Audit.id == audit.id) \
                    .count()
    medium_count = VulnerabilityDiscovered.query \
                    .join(Audit, VulnerabilityDiscovered.audit_id == Audit.id) \
                    .join(User, Audit.user_id == User.id) \
                    .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
                    .filter(VulnerabilityTemplates.severity == "MEDIUM") \
                    .filter(Audit.id == audit.id) \
                    .count()
    low_count = VulnerabilityDiscovered.query \
                    .join(Audit, VulnerabilityDiscovered.audit_id == Audit.id) \
                    .join(User, Audit.user_id == User.id) \
                    .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
                    .filter(VulnerabilityTemplates.severity == "LOW") \
                    .filter(Audit.id == audit.id) \
                    .count()
    info_count = VulnerabilityDiscovered.query \
                    .join(Audit, VulnerabilityDiscovered.audit_id == Audit.id) \
                    .join(User, Audit.user_id == User.id) \
                    .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
                    .filter(VulnerabilityTemplates.severity == "INFO") \
                    .filter(Audit.id == audit.id) \
                    .count()
    vulnerability_data = {}
    for vuln in vulnerabilities:
        vulnerability_data[vuln.name] = eval(vuln.data)
    content = render_template(
                            'utils/report_template.html', 
                            audit=audit,  
                            critical_count=critical_count,
                            high_count=high_count,
                            medium_count=medium_count,
                            low_count=low_count,
                            info_count=info_count,
                            vulnerabilities=vulnerabilities,
                            vulnerability_data=vulnerability_data
                            )
    report = task_queue.enqueue(generate_report, content)
    return report.get_id()




@utils.route('/report/<string:audit_id>/download/<job_id>', methods=['GET'])
@login_required
@limiter.limit("5/minute")
def download_report(audit_id,job_id):
    report = task_queue.fetch_job(job_id)
    if report.is_finished:
        pdf_file = report.result
        response = make_response(pdf_file)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{audit_id}-report.pdf"'
        return response, 200
    return 'processing', 403