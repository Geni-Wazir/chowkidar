from flask import render_template, url_for, flash, redirect, request, Blueprint, session, make_response, send_from_directory, current_app, abort
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




@utils.errorhandler(429)
def ratelimit_handler(e):
    flash("You have exceeded the rate limit. Please try again later.", "info")
    return redirect(url_for('utils.home'))




@utils.route('/favicon.ico')
def favicon():
    return send_from_directory(current_app.root_path, 'static/favicon.ico', mimetype='image/vnd.microsoft.icon')




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




@utils.route('/auth')
def auth():
    return google.authorize(callback=url_for('utils.auth_callback', _external=True))




@utils.route('/auth/callback')
def auth_callback():
    token = google.authorized_response()

    if token:
        session['google_token'] = (token['access_token'], '')
        user_info = google.get('userinfo')
        email = user_info.data.get("email")
        name = user_info.data.get("name")

        user = User.query.filter_by(email=email).first()

        if not user:
            user = User(email=email, name=name, admin=email in admins_list)
            db.session.add(user)
            db.session.commit()

        login_user(user)
        return redirect(url_for('audits.audit_list'))

    flash('Login failed', 'danger')
    return redirect(url_for('utils.home'))




@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')




def get_vulnerability_counts(user_id, audit_id=None):
    filters = [User.id == user_id]
    if audit_id:
        filters.append(Audit.id == audit_id)

    vulnerability_counts = {}
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        count = VulnerabilityDiscovered.query \
            .join(Audit, VulnerabilityDiscovered.audit_id == Audit.id) \
            .join(User, Audit.user_id == User.id) \
            .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
            .filter(VulnerabilityTemplates.severity == severity) \
            .filter(*filters) \
            .count()
        vulnerability_counts[f'{severity.lower()}_count'] = count
    return vulnerability_counts




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

    vulnerability_counts = get_vulnerability_counts(current_user.id)

    if request.method == 'GET':
        form.api_key.data = current_user.wpscan_api

    return render_template(
        'utils/profile.html',
        title="Profile",
        form=form,
        audit_count=audit_count,
        audit_completed_count=audit_completed_count,
        **vulnerability_counts
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
        contact_post_form(form)
    return render_template('utils/contact.html', title="Contact", form=form)




@limiter.limit("2/minute")
def contact_post_form(form):
    if form.validate_on_submit():
        recipient = [os.environ['MAIL_USERNAME']]
        subject = f'{form.name.data} Wants to Connect'
        message = f'Name: {form.name.data} <p>Email: {form.email.data}</p> <p style="margin-top:2rem;">Message:</p><p style="margin-left:2rem;">{form.message.data}</p>' 
        msg = Message(
            subject,
            sender=os.environ['MAIL_USERNAME'],
            recipients=recipient,
            html=message
        )
        try:
            mail.send(msg)
            flash('Your message has been successfully delivered.', 'success')
        except Exception:
            flash('Unable to deliver your message, please use an alternative method to communicate.', 'danger')
    else:
        errors = list(form.errors.values())
        if errors:
            flash(", ".join(errors[0]), 'info')
        else:
            flash('Unable to deliver your message, please use an alternative method to communicate.', 'danger')
    return redirect(url_for('utils.contact'))




@utils.route('/report/<int:audit_id>')
@login_required
@limiter.limit("10/minute")
def report(audit_id):
    if current_user.admin:
        audit = Audit.query.filter_by(id=audit_id).first()
    else:
        audit = Audit.query.filter_by(id=audit_id, Auditor=current_user).first()
    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('audits.audit_list'))

    vulnerabilities = VulnerabilityDiscovered.query \
        .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
        .filter(VulnerabilityDiscovered.audit_id == audit.id) \
        .order_by(VulnerabilityTemplates.cvss.desc()).all()
    try:
        vulnerability_data = {
            vuln.id: eval(vuln.data) for vuln in vulnerabilities
        }

        content = render_template(
            'utils/report_template.html',
            audit=audit,
            vulnerabilities=vulnerabilities,
            vulnerability_data=vulnerability_data,
            **get_vulnerability_counts(audit.Auditor.id, audit_id=audit.id)
        )

        gen_report = task_queue.enqueue(generate_report, content)
        return gen_report.get_id()
    except:
        abort(500)




@utils.route('/report/<string:audit_id>/download/<job_id>', methods=['GET'])
@login_required
@limiter.limit("10/minute")
def download_report(audit_id, job_id):
    report_job = task_queue.fetch_job(job_id)

    if report_job.is_finished:
        pdf_file = report_job.result
        response = make_response(pdf_file)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="{audit_id}-report.pdf"'
        return response, 200

    return 'processing', 403




@utils.route('/audit/progress/<int:audit_id>')
@login_required
def audit_progress(audit_id):
    if current_user.admin:
        audit = Audit.query.filter_by(id=audit_id).first()
    else:
        audit = Audit.query.filter_by(id=audit_id, Auditor=current_user).first()

    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('admin_view.all_audits'))
    response = {
        'name': audit.name,
        'status': audit.status,
        'progress': audit.progress,
        'msg': audit.progress_mmsg
    }
    return response