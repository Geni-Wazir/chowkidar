from flask import render_template,Blueprint, flash, redirect, url_for, request, abort
from flask_login import current_user, login_required
from chowkidar.models import Audit, ScanResults, VulnerabilityDiscovered, VulnerabilityTemplates, db
from chowkidar import limiter, task_queue, mail
from chowkidar.audits.forms import AuditForm, UpdateAuditForm
from chowkidar.utils.scheduler import run_scan, delete_container, remove_task
import os
from flask_mail import Message




audits = Blueprint('audits', __name__)




@audits.route('/audits')
@login_required
def audit_list():
    all_audit = Audit.query.filter_by(Auditor=current_user).order_by(Audit.id.desc())
    return render_template('audits/audits.html', title="Audits", audits=all_audit)




@limiter.limit("5/minute")
def add_audit_post(form):
    audit = Audit(
        name=form.name.data.lower(),
        url=form.url.data,
        tools=str({
            'nmap': form.nmap.data,
            'dirsearch': form.dirsearch.data,
            'headers': form.headers.data,
            'testssl': form.testssl.data,
            'nuclei': form.nuclei.data,
            'sublister': form.sublister.data,
            'wpscan': form.wpscan.data,
        }),
        Auditor=current_user
    )
    db.session.add(audit)
    db.session.commit()




@audits.route('/audits/new', methods=['GET', 'POST'])
@login_required
def add_audit():
    form = AuditForm()
    if form.validate_on_submit():
        if current_user.scan_available:
            if any(list(form.data.values())[2:-1]):
                add_audit_post(form)
                flash('Audit has been Added to Your Universe', 'success')
                return redirect(url_for('audits.audit_list'))
            flash('Boost Your Scan with at Least One Empowering Tool', 'info')
        else:
            flash('Your Scan Count is Low! Connect with Admin for Additional Scans', 'info')
    else:
        errors = list(form.errors.values())
        if errors:
            flash(", ".join(errors[0]), 'info')
    return render_template('audits/add_audit.html', title="Add Audit", form=form, legend="New Audit")




@audits.get('/audits/<string:audit_name>')
@login_required
def audit(audit_name):
    audit = Audit.query.filter_by(name=audit_name, Auditor=current_user).first()
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
        return render_template('audits/add_audit.html', title="Audit Info", audit=audit, form=form, legend="Audit Insights")
    else:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('audits.audit_list'))




@audits.post('/audits/<string:audit_name>')
@login_required
@limiter.limit("5/minute")
def audit_post(audit_name):
    audit = Audit.query.filter_by(name=audit_name, Auditor=current_user).first()
    if audit:
        form = UpdateAuditForm()
        if form.validate_on_submit():
            if audit.status == 'unscanned':
                if any(list(form.data.values())[:-1]):
                    tools = str({
                        'nmap': form.nmap.data,
                        'dirsearch': form.dirsearch.data,
                        'headers': form.headers.data,
                        'testssl': form.testssl.data,
                        'nuclei': form.nuclei.data,
                        'sublister': form.sublister.data,
                        'wpscan': form.wpscan.data,
                    })
                    audit.tools = tools
                    db.session.commit()
                    flash('The audit has been upgraded', 'success')
                    return redirect(url_for('audits.audit', audit_name=audit.name))
                else:
                    flash('Boost Your Scan with at Least One Empowering Tool', 'info')
            else:
                flash('Audit can not be updated', 'info')
        return redirect(url_for('audits.audit', audit_name=audit.name))
    else:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('audits.audit_list'))




@limiter.limit("5/minute")
@audits.route('/audits/<string:audit_name>/delete', methods=['GET', 'POST'])
@login_required
def delete_audit(audit_name):
    audit = Audit.query.filter_by(name=audit_name, Auditor=current_user).first()

    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('audits.audit_list'))

    if audit.status == 'scanning':
        if audit.container_id:
            stop_scan = delete_container(audit.container_id)
        else:
            stop_scan = remove_task(audit.task_id)
        
        if not stop_scan:
            flash(f'Apologies, the deletion of audit {audit.name} has failed', 'danger')
            return redirect(url_for('audits.audit_list'))

    db.session.delete(audit)
    db.session.commit()
    flash(f'The audit {audit.name} has been successfully removed', 'success')
    
    return redirect(url_for('audits.audit_list'))




@limiter.limit("5/minute")
@audits.route('/audits/<string:audit_name>/scan', methods=['GET', 'POST'])
@login_required
def scan_audit(audit_name):
    if not current_user.scan_available:
        flash('Your Scan Count is Low! Connect with Admin for Additional Scans', 'info')
        return redirect(url_for('audits.audit_list'))

    audit = Audit.query.filter_by(name=audit_name, Auditor=current_user).first()
    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('audits.audit_list'))

    if audit.status != 'unscanned':
        flash(f'Initiating the scan for {audit.name} is not possible', 'info')
        return redirect(url_for('audits.audit_list'))

    add_vulnerability_api = os.getenv('SERVER_URL') + url_for('audits.add_vulnerability')
    scan_result_api = os.getenv('SERVER_URL') + url_for('audits.add_scan_result')
    scan_status_api = os.getenv('SERVER_URL') + url_for('audits.scan_status')
    secret_key = os.environ.get('SCANNER_SECRET_KEY')

    scan_task = task_queue.enqueue(run_scan, args=(secret_key, scan_result_api, add_vulnerability_api, scan_status_api, audit), job_timeout=-1)
    audit.task_id = scan_task.id
    audit.status = 'scanning'
    
    if not current_user.admin:
        current_user.scan_available -= 1
    
    db.session.commit()
    flash(f'Congratulations! Your {audit.name} scan has been successfully started.', 'success')
    return redirect(url_for('audits.audit_list'))




@audits.route('/audits/containerid', methods=['POST'])
def get_container():
    data = request.json
    secret_key = data.get('secret_key')
    if secret_key == os.environ.get('SCANNER_SECRET_KEY'):
        audit_id = data.get('audit_id')
        container_id = data.get('container_id')
        if audit_id and container_id:
            audit = Audit.query.filter_by(id=audit_id).first()
            if audit:
                audit.container_id = container_id
                db.session.commit()
                return 'ok', 200
        abort(404)  # Missing audit_id or container_id
    abort(403)  # Incorrect secret_key




@audits.route('/audits/<string:audit_name>/stop', methods=['GET', 'POST'])
@login_required
def stop_scan(audit_name):
    audit = Audit.query.filter_by(name=audit_name, Auditor=current_user).first()

    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('audits.audit_list'))

    if audit.status != 'scanning':
        flash(f'This action cannot be performed for {audit.name}', 'info')
        return redirect(url_for('audits.audit_list'))

    if audit.container_id:
        stop_scan = delete_container(audit.container_id)
    else:
        stop_scan = remove_task(audit.task_id)

    if not stop_scan:
        flash(f'Apologies, the stopping of scan for {audit.name} has failed', 'danger')
        return redirect(url_for('audits.audit_list'))

    audit.status = 'stopped'
    db.session.commit()
    flash(f'Your Scan for {audit.name} has been stopped', 'success')

    return redirect(url_for('audits.audit_list'))




@audits.route('/audits/vulnerability/add', methods=['POST'])
def add_vulnerability():
    data = request.json
    if data['secret_key'] == os.environ['SCANNER_SECRET_KEY']:
        audit = Audit.query.filter_by(id=data['audit_id']).first()
        if audit:
            existing_vulnerabilities = [v.name for v in VulnerabilityDiscovered.query.filter_by(Audit=audit).all()]
            for vul in data['vulnerabilities']:
                if vul not in existing_vulnerabilities:
                    template = VulnerabilityTemplates.query.filter_by(name=vul).first()
                    new_vuln = VulnerabilityDiscovered(name=vul, data=str(data['vulnerabilities'][vul]) ,Audit=audit, Template=template)
                    db.session.add(new_vuln)
            db.session.commit()
            return 'ok', 200
        abort(404)  # audit not found
    abort(403)  # Incorrect secret_key




@audits.route('/audits/result/add', methods=['POST'])
def add_scan_result():
    data = request.json
    if data['secret_key'] == os.environ['SCANNER_SECRET_KEY']:
        audit = Audit.query.filter_by(id=data['audit_id']).first()
        scan_result = ScanResults.query.filter_by(Audit = audit).first()
        if audit:
            if not scan_result:
                scan_result = ScanResults(Audit=audit)
                db.session.add(scan_result)
            setattr(scan_result, data['tool'], data['output'])
            db.session.commit()
            return 'ok', 200
        abort(404)  # audit not found
    abort(403)  # Incorrect secret_key




@audits.route('/audits/scan/status', methods=['POST'])
def scan_status():
    data = request.json
    if data['secret_key'] == os.environ['SCANNER_SECRET_KEY']:
        audit = Audit.query.filter_by(id=data['audit_id']).first()
        scan_result = ScanResults.query.filter_by(Audit = audit).first()
        if audit:
            if not scan_result:
                scan_result = ScanResults(Audit=audit)
                db.session.add(scan_result)
            if data['status'] == 'stopped':
                for tool in data['tools']:
                    setattr(scan_result, tool, "URL not reachable")
            audit.status = data['status']
            db.session.commit()
            reciever = [audit.Auditor.email]
            subject = f'Completion of Vulnerability Scan for {audit.name}'
            message = render_template('audits/scan_complete_mail.html', audit=audit)
            msg = Message(subject, sender=os.environ['MAIL_USERNAME'], recipients=reciever)
            msg.html = message
            try:
                mail.send(msg)
            except:
                pass
            delete_container(audit.container_id)
            return "ok", 200
        abort(404)  # audit not found
    abort(403)  # Incorrect secret_key




@audits.route('/audits/<string:audit_name>/vulnerability/<string:vulnerability_name>')
@login_required
def vulnerability(audit_name, vulnerability_name):
    audit = Audit.query.filter_by(name=audit_name, Auditor=current_user).first()

    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('audits.audit_list'))

    if audit.status == 'unscanned':
        flash(f'The audit {audit_name} has not been scanned yet.', 'info')
        return redirect(url_for('audits.audit_list'))

    vulnerability = VulnerabilityDiscovered.query.filter_by(Audit=audit, name=vulnerability_name).first()
    template = VulnerabilityTemplates.query.filter_by(name=vulnerability_name).first()

    if not vulnerability or not template:
        flash('Vulnerability or template not found.', 'danger')
        return redirect(url_for('audits.audit_list'))

    return render_template('audits/vulnerability.html', title="Admin", vulnerability=eval(vulnerability.data), template=template)




@audits.route('/audits/<string:audit_name>/vulnerability')
@login_required
def vulnerabilities(audit_name):
    audit = Audit.query.filter_by(name=audit_name, Auditor=current_user).first()

    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('audits.audit_list'))

    if audit.status == 'unscanned':
        flash(f'The audit {audit_name} has not been scanned yet.', 'info')
        return redirect(url_for('audits.audit_list'))

    vulnerabilities = VulnerabilityDiscovered.query \
        .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
        .filter(VulnerabilityDiscovered.audit_id == audit.id) \
        .order_by(VulnerabilityTemplates.cvss.desc()).all()

    return render_template('audits/vulnerabilities.html', title="Vulnerabilities", audit=audit, vulnerabilities=vulnerabilities)




@audits.route('/audits/<string:audit_name>/scan-output')
@login_required
def scan_result(audit_name):
    audit = Audit.query.filter_by(name=audit_name, Auditor=current_user).first()

    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('audits.audit_list'))

    if audit.status == 'unscanned':
        flash(f'The audit {audit_name} has not been scanned yet.', 'info')
        return redirect(url_for('audits.vulnerabilities', audit_name=audit_name))

    output = ScanResults.query.filter_by(Audit=audit).first()

    if not output:
        flash(f'Currently, there are no scan results available for {audit_name}', 'info')
        return redirect(url_for('audits.vulnerabilities', audit_name=audit_name))

    return render_template('audits/scan_result.html', title="Scan Results", audit=audit, output=output)