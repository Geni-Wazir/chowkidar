from flask import render_template,Blueprint, flash, redirect, url_for
from flask_login import current_user, login_required
from chowkidar.models import User, Audit, ScanResults, VulnerabilityDiscovered, VulnerabilityTemplates, db
from chowkidar.admin.forms import UpdateAuditForm
from chowkidar import limiter, task_queue
from chowkidar.utils.scheduler import delete_container, remove_task, run_scan, generate_report
import os
from chowkidar.utils.routes import get_vulnerability_counts




admin_view = Blueprint('admin_view', __name__)




@admin_view.route('/admin/audits-all')
@login_required
def all_audits():
    if not current_user.admin:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('audits.audit_list'))
    audits = Audit.query.order_by(Audit.id.desc()).all()
    return render_template('admin/audits.html', title="Admin", audits=audits)




@admin_view.get('/admin/audits/<string:user_email>/<string:audit_name>')
@login_required
def admin_audit(user_email, audit_name):
    if not current_user.admin:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('audits.audit_list'))
    
    user = User.query.filter_by(email=user_email).first()
    audit = Audit.query.filter_by(name=audit_name, Auditor=user).first()
    if audit:
        tools = eval(audit.tools)
        form = UpdateAuditForm()
        form.nmap.data = tools['nmap']
        form.dirsearch.data = tools['dirsearch']
        form.headers.data = tools['headers']
        form.testssl.data = tools['testssl']
        form.nuclei.data = tools['nuclei']
        form.sublister.data = tools['sublister']
        form.wpscan.data = tools['wpscan']
    else:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('admin_view.all_audits'))
    return render_template('admin/add_audit.html', title="Admin", audit=audit, form=form, legend="Audit Insights")




@admin_view.route('/admin/audits/<string:user_email>/<string:audit_name>', methods=['POST'])
@login_required
@limiter.limit("5/minute")
def admin_audit_post(user_email, audit_name):
    if not current_user.admin:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('audits.audit_list'))
    
    user = User.query.filter_by(email=user_email).first()
    audit = Audit.query.filter_by(name=audit_name, Auditor=user).first()

    if not audit:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('admin_view.all_audits'))

    form = UpdateAuditForm()

    if form.validate_on_submit():
        if audit.status == 'unscanned':
            if any(list(form.data.values())[2:-1]):
                audit.tools=str({
                    'nmap': form.nmap.data,
                    'dirsearch': form.dirsearch.data,
                    'headers': form.headers.data,
                    'testssl': form.testssl.data,
                    'nuclei': form.nuclei.data,
                    'sublister': form.sublister.data,
                    'wpscan': form.wpscan.data,
                }),
                db.session.commit()
                flash('The audit has been upgraded', 'success')
            else:
                flash('Boost Your Scan with at Least One Empowering Tool', 'info')
        else:
            flash('Audit can not be updated', 'info')

    return redirect(url_for('admin_view.admin_audit', user_email=user.email, audit_name=audit.name))




@limiter.limit("5/minute")
@admin_view.route('/admin/audits/<string:user_email>/<string:audit_name>/delete', methods=['GET', 'POST'])
@login_required
def admin_delete_audit(user_email, audit_name):
    if not current_user.admin:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('audits.audit_list'))
    
    user = User.query.filter_by(email=user_email).first()
    audit = Audit.query.filter_by(name=audit_name, Auditor=user).first()

    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('admin_view.all_audits'))

    if audit.status == 'scanning':
        if audit.container_id:
            stop_scan = delete_container(audit.container_id)
        else:
            stop_scan = remove_task(audit.task_id)
        
        if not stop_scan:
            flash(f'Apologies, the deletion of audit {audit.name} has failed', 'danger')
            return redirect(url_for('admin_view.all_audits'))

    db.session.delete(audit)
    db.session.commit()
    flash(f'The audit {audit.name} has been successfully removed', 'success')
    
    return redirect(url_for('admin_view.all_audits'))




@limiter.limit("5/minute")
@admin_view.route('/admin/audits/<string:user_email>/<string:audit_name>/scan', methods=['GET', 'POST'])
@login_required
def admin_scan_audit(user_email, audit_name):
    if not current_user.admin:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('audits.audit_list'))

    user = User.query.filter_by(email=user_email).first()
    audit = Audit.query.filter_by(name=audit_name, Auditor=user).first()
    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('admin_view.all_audits'))

    if audit.status != 'unscanned':
        flash(f'Initiating the scan for {audit.name} is not possible', 'info')
        return redirect(url_for('admin_view.all_audits'))

    add_vulnerability_api = 'http://localhost' + url_for('audits.add_vulnerability')
    scan_result_api = 'http://localhost' + url_for('audits.add_scan_result')
    scan_status_api = 'http://localhost' + url_for('audits.scan_status')
    secret_key = os.environ.get('SCANNER_SECRET_KEY')

    scan_task = task_queue.enqueue(run_scan, args=(secret_key, scan_result_api, add_vulnerability_api, scan_status_api, audit), job_timeout='10h')
    audit.task_id = scan_task.id
    audit.status = 'scanning'
    
    db.session.commit()
    flash(f'Congratulations! Your {audit.name} scan has been successfully started.', 'success')
    return redirect(url_for('admin_view.all_audits'))




@limiter.limit("5/minute")
@admin_view.route('/admin/audits/<string:user_email>/<string:audit_name>/rescan', methods=['POST'])
@login_required
def admin_rescan_audit(user_email, audit_name):
    if not current_user.admin:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('audits.audit_list'))

    user = User.query.filter_by(email=user_email).first()
    audit = Audit.query.filter_by(name=audit_name, Auditor=user).first()
    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('admin_view.all_audits'))

    if audit.status != 'finished':
        flash(f'Initiating the Rescan for {audit.name} is not possible', 'info')
        return redirect(url_for('admin_view.admin_vulnerabilities', user_email=user.email, audit_name=audit_name))

    if not audit.scan_verified:
        flash(f'{audit.name} scan is not verified', 'info')
        return redirect(url_for('admin_view.admin_vulnerabilities', user_email=user.email, audit_name=audit_name))

    # add_vulnerability_api = os.getenv('SERVER_URL') + url_for('audits.add_vulnerability')
    # scan_result_api = os.getenv('SERVER_URL') + url_for('audits.add_scan_result')
    # scan_status_api = os.getenv('SERVER_URL') + url_for('audits.scan_status')
    # secret_key = os.environ.get('SCANNER_SECRET_KEY')

    # scan_task = task_queue.enqueue(run_scan, args=(secret_key, scan_result_api, add_vulnerability_api, scan_status_api, audit), job_timeout=-1)
    # audit.task_id = scan_task.id
    # audit.status = 'rescanning'

    
    db.session.commit()
    flash(f'Congratulations! Your {audit.name} Rescan has been successfully started.', 'success')
    return redirect(url_for('admin_view.admin_vulnerabilities', user_email=user.email, audit_name=audit_name))




@admin_view.route('/admin/audits/<string:user_email>/<string:audit_name>/stop', methods=['GET', 'POST'])
@login_required
def admin_stop_scan(user_email, audit_name):
    if not current_user.admin:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('audits.audit_list'))
    
    user = User.query.filter_by(email=user_email).first()
    audit = Audit.query.filter_by(name=audit_name, Auditor=user).first()

    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('admin_view.all_audits'))

    if audit.status != 'scanning':
        flash(f'This action cannot be performed for {audit.name}', 'info')
        return redirect(url_for('admin_view.all_audits'))

    if audit.container_id:
        stop_scan = delete_container(audit.container_id)
    else:
        stop_scan = remove_task(audit.task_id)

    if not stop_scan:
        flash(f'Apologies, the stopping of scan for {audit.name} has failed', 'danger')
        return redirect(url_for('admin_view.all_audits'))

    audit.status = 'stopped'
    db.session.commit()
    flash(f'Your Scan for {audit.name} has been stopped', 'success')

    return redirect(url_for('admin_view.all_audits'))




@admin_view.route('/admin/audits/<string:user_email>/<string:audit_name>/vulnerability')
@login_required
def admin_vulnerabilities(user_email, audit_name):
    if not current_user.admin:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('audits.audit_list'))

    user = User.query.filter_by(email=user_email).first()
    audit = Audit.query.filter_by(name=audit_name, Auditor=user).first()

    if not audit:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('admin_view.all_audits'))

    if audit.status == 'unscanned':
        flash(f'The audit {audit_name} has not been scanned yet.', 'info')
        return redirect(url_for('admin_view.all_audits'))

    vulnerabilities = VulnerabilityDiscovered.query \
        .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
        .filter(VulnerabilityDiscovered.audit_id == audit.id) \
        .order_by(VulnerabilityTemplates.cvss.desc()).all()

    return render_template('admin/vulnerabilities.html', title="Admin", audit=audit, vulnerabilities=vulnerabilities)




@admin_view.route('/admin/audits/<string:user_email>/<string:audit_name>/vulnerability/<string:vulnerability_name>')
@login_required
def admin_vulnerability(user_email, audit_name, vulnerability_name):
    if not current_user.admin:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('audits.audit_list'))

    user = User.query.filter_by(email=user_email).first()
    audit = Audit.query.filter_by(name=audit_name, Auditor=user).first()

    if not audit:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('admin_view.all_audits'))

    if audit.status == 'unscanned':
        flash(f'The audit {audit_name} has not been scanned yet.', 'info')
        return redirect(url_for('admin_view.all_audits'))

    vulnerability = VulnerabilityDiscovered.query.filter_by(Audit=audit, name=vulnerability_name).first()
    template = VulnerabilityTemplates.query.filter_by(name=vulnerability_name).first()

    if not vulnerability or not template:
        flash('Vulnerability or template not found.', 'danger')
        return redirect(url_for('admin_view.all_audits'))

    return render_template('admin/vulnerability.html', title="Admin", vulnerability=eval(vulnerability.data), template=template)




@admin_view.route('/admin/audits/<string:user_email>/<string:audit_name>/scan-output')
@login_required
def admin_scan_result(user_email, audit_name):
    if not current_user.admin:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('audits.audit_list'))

    user = User.query.filter_by(email=user_email).first()
    audit = Audit.query.filter_by(name=audit_name, Auditor=user).first()

    if not audit:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('admin_view.all_audits'))

    if audit.status == 'unscanned':
        flash(f'The audit {audit_name} has not been scanned yet.', 'info')
        return redirect(url_for('admin_view.all_audits'))

    output = ScanResults.query.filter_by(Audit=audit).first()

    if not output:
        flash(f'Currently, there are no scan results available for {audit_name}', 'info')
        return redirect(url_for('admin_view.admin_vulnerabilities', user_email=user.email, audit_name=audit_name))
    
    vulnerabilities = VulnerabilityDiscovered.query \
        .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
        .filter(VulnerabilityDiscovered.audit_id == audit.id).count()

    return render_template('admin/scan_result.html', title="Admin", audit=audit, output=output, vulnerabilities=vulnerabilities)




@admin_view.route('/admin/audits/<string:user_email>/<string:audit_name>/verify')
@login_required
def admin_scan_verify(user_email, audit_name):
    if not current_user.admin:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('audits.audit_list'))
    
    user = User.query.filter_by(email=user_email).first()
    audit = Audit.query.filter_by(name=audit_name, Auditor=user).first()

    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('admin_view.all_audits'))

    if audit.status == 'finished':
        audit.scan_verified = True
        db.session.commit()
        flash(f'Scan {audit_name} verified successfuly', 'success')
        return redirect(url_for('admin_view.admin_vulnerabilities', user_email=user.email, audit_name=audit_name))
    
    flash(f'The audit {audit_name} has not been scanned yet.', 'info')
    return redirect(url_for('admin_view.admin_vulnerabilities', user_email=user.email, audit_name=audit_name))