from flask import render_template,Blueprint, flash, redirect, url_for, request, abort
from flask_login import current_user, login_required
from chowkidar.models import Audit, ScanResults, VulnerabilityDiscovered, VulnerabilityTemplates, CloudRegions, CloudServices, db
from chowkidar import limiter, task_queue, mail
from chowkidar.audits.forms import WebAuditForm, WebUpdateAuditForm, CloudAuditForm, CloudUpdateAuditForm
from chowkidar.utils.scheduler import run_scan, delete_container, remove_task
import os
from flask_mail import Message
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader





audits = Blueprint('audits', __name__)


def highlight_raw_secrets(source_code, raw_secrets):
    secrets = raw_secrets.split(", ")
    for secret in secrets:
        source_code = source_code.replace(secret, f'<span class="highlight">{secret}</span>')
    return source_code

env = Environment(loader=FileSystemLoader('templates'))  # Update 'templates' with your templates directory
env.filters['highlight_raw_secrets'] = highlight_raw_secrets

@audits.route('/audits')
@login_required
def audit_list():
    all_audit = Audit.query.filter_by(Auditor=current_user).order_by(Audit.id.desc())
    return render_template('audits/audits.html', title="Audits", audits=all_audit)




@limiter.limit("5/minute")
def add_web_audit(webform):
    audit = Audit(
        name=webform.name.data.lower(),
        url=webform.url.data,
        tools=str({
            'nmap': webform.nmap.data,
            'dirsearch': webform.dirsearch.data,
            'headers': webform.headers.data,
            'testssl': webform.testssl.data,
            'nuclei': webform.nuclei.data,
            'sublister': webform.sublister.data,
            'wpscan': webform.wpscan.data,
        }),
        Auditor=current_user,
        date = datetime.now(timezone.utc)
    )
    db.session.add(audit)
    db.session.commit()




@limiter.limit("5/minute")
def add_cloud_audit(cloudform):
    audit = Audit(
        name=cloudform.name.data.lower(),
        asset_type=cloudform.asset_type.data,
        access_id=cloudform.access_id.data,
        secret_key=cloudform.secret_key.data,
        regions=str(cloudform.regions.data),
        services=str(cloudform.services.data),
        Auditor=current_user,
        date = datetime.now(timezone.utc)
    )
    db.session.add(audit)
    db.session.commit()




@audits.route('/audits/new', methods=['GET', 'POST'])
@login_required
def add_audit():
    webform = WebAuditForm()
    cloudform = CloudAuditForm()
    regions = CloudRegions.query.filter_by(asset_type='aws')
    services = CloudServices.query.filter_by(asset_type='aws')
    cloudform.regions.choices = [ (region.name, region.name) for region in regions ]
    cloudform.services.choices = [ (service.name, service.name.replace('_', ' ')) for service in services ]
    if webform.validate_on_submit():
        if current_user.scan_available:
            if any(list(webform.data.values())[2:-1]):
                add_web_audit(webform)
                flash('Audit has been Added to Your Universe', 'success')
                return redirect(url_for('audits.audit_list'))
            flash('Boost Your Scan with At Least One Empowering Tool', 'info')
        else:
            flash('Your Scan Count is Low! Connect with Admin for Additional Scans', 'info')
    elif cloudform.validate_on_submit():
        if current_user.scan_available:
            if any(list(cloudform.services.data)):
                add_cloud_audit(cloudform)
                flash('Audit has been Added to Your Universe', 'success')
                return redirect(url_for('audits.audit_list'))
            flash('Boost Your Scan with At Least One Cloud Service', 'info')
        else:
            flash('Your Scan Count is Low! Connect with Admin for Additional Scans', 'info')
    else:
        errors = []
        if cloudform.access_id.data:
            errors = list(cloudform.errors.values())
        elif webform.name.data:
            errors = list(webform.errors.values())
        if errors:
            flash(", ".join(errors[0]), 'info')
    return render_template('audits/add_audit.html', title="Add Audit", webform=webform, cloudform=cloudform, legend="New Audit")




@audits.get('/audits/<string:audit_name>')
@login_required
def audit(audit_name):
    audit = Audit.query.filter_by(name=audit_name, Auditor=current_user).first()
    webform = WebUpdateAuditForm()
    cloudform = CloudUpdateAuditForm()
    regions = CloudRegions.query.filter_by(asset_type='aws')
    services = CloudServices.query.filter_by(asset_type='aws')
    cloudform.regions.choices = [ (region.name, region.name) for region in regions ]
    cloudform.services.choices = [ (service.name, service.name.replace('_', ' ')) for service in services ]
    if audit:
        if 'web' in audit.asset_type:
            tools = eval(audit.tools)
            webform.nmap.data = tools['nmap']
            webform.dirsearch.data = tools['dirsearch']
            webform.headers.data = tools['headers']
            webform.testssl.data = tools['testssl']
            webform.nuclei.data = tools['nuclei']
            webform.sublister.data = tools['sublister']
            webform.wpscan.data = tools['wpscan']
        elif 'cloud' in audit.asset_type:
            cloudform.regions.data = eval(audit.regions)
            cloudform.services.data = eval(audit.services)
        return render_template('audits/update_audit.html', title="Audit Info", audit=audit, webform=webform, cloudform=cloudform, legend="Audit Insights")
    else:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('audits.audit_list'))




@audits.post('/audits/<string:audit_name>')
@login_required
@limiter.limit("5/minute")
def audit_post(audit_name):
    audit = Audit.query.filter_by(name=audit_name, Auditor=current_user).first()
    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('audits.audit_list'))

    webform = WebUpdateAuditForm()
    cloudform = CloudUpdateAuditForm()

    # Set choices for cloud regions and services
    regions = CloudRegions.query.filter_by(asset_type='aws')
    services = CloudServices.query.filter_by(asset_type='aws')
    cloudform.regions.choices = [(region.name, region.name) for region in regions]
    cloudform.services.choices = [(service.name, service.name.replace('_', ' ')) for service in services]

    # Process web audit
    if 'web' in audit.asset_type and webform.validate_on_submit():
        if audit.status == 'unscanned':
            if any(list(webform.data.values())[:-1]):  # Exclude CSRF token
                audit.tools = str({
                    'nmap': webform.nmap.data,
                    'dirsearch': webform.dirsearch.data,
                    'headers': webform.headers.data,
                    'testssl': webform.testssl.data,
                    'nuclei': webform.nuclei.data,
                    'sublister': webform.sublister.data,
                    'wpscan': webform.wpscan.data,
                })
                db.session.commit()
                flash('The audit has been upgraded', 'success')
                return redirect(url_for('audits.audit', audit_name=audit.name))
            else:
                flash('Boost Your Scan with at Least One Empowering Tool', 'info')
        else:
            flash('Audit cannot be updated', 'info')

    # Process cloud audit
    elif 'cloud' in audit.asset_type and cloudform.validate_on_submit():
        if any(cloudform.services.data):
            audit.regions = str(cloudform.regions.data)
            audit.services = str(cloudform.services.data)
            db.session.commit()
            flash('The audit has been upgraded', 'success')
            return redirect(url_for('audits.audit', audit_name=audit.name))
        else:
            flash('Boost Your Scan with At Least One Cloud Service', 'info')
    else:
        # Handle form validation errors for cloud form
        errors = cloudform.errors.get('services')
        if errors:
            flash(", ".join(errors), 'info')

    return redirect(url_for('audits.audit', audit_name=audit.name))



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




def initiate_scan(current_user, audit, status, db):

    add_vulnerability_api = os.getenv('SERVER_URL') + url_for('audits.add_vulnerability')
    scan_result_api = os.getenv('SERVER_URL') + url_for('audits.add_scan_result')
    scan_status_api = os.getenv('SERVER_URL') + url_for('audits.scan_status')
    secret_key = os.environ.get('SCANNER_SECRET_KEY')

    scan_task = task_queue.enqueue(run_scan, args=(secret_key, scan_result_api, add_vulnerability_api, scan_status_api, audit), job_timeout=-1)
    audit.task_id = scan_task.id
    audit.status = status
    audit.scan_date = datetime.now(timezone.utc)

    if not current_user.admin:
        current_user.scan_available -= 1
    db.session.commit()



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

    if audit.asset_type not in ['web', 'cloud_aws']:
        flash(f'Unable to start your scan. Currently, we only support WEB and AWS scans.', 'info')
        return redirect(url_for('audits.audit_list'))

    try:
        initiate_scan(current_user, audit, 'scanning', db)
    except:
        flash(f'Error Initiating Scan for {audit.name}', 'danger')
        return redirect(url_for('audits.audit_list'))
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
    audit.progress_msg = 'Scan Stopped'
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
                scan_result.cloud = '{}'
                db.session.add(scan_result)
            if 'web' in audit.asset_type:
                if data['tool']:
                    setattr(scan_result, data['tool'], str(data['output']))
            elif 'cloud' in audit.asset_type:
                output = eval(scan_result.cloud)
                output.update(data['output'])
                setattr(scan_result, data['tool'], str(output))
            audit.progress = data['progress']
            audit.progress_msg = data['progress_msg']
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
        vulnerabilities = VulnerabilityDiscovered.query \
        .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
        .filter(VulnerabilityDiscovered.audit_id == audit.id) \
        .order_by(VulnerabilityTemplates.cvss.desc()).all()
        if audit:
            if not scan_result:
                scan_result = ScanResults(Audit=audit)
                db.session.add(scan_result)
            if 'web' in audit.asset_type and data['status'] == 'stopped':
                for tool in data['tools']:
                    setattr(scan_result, tool, "URL not reachable")
            audit.progress = data['progress']
            audit.progress_msg = data['progress_msg']
            audit.status = data['status']
            db.session.commit()
            if data['status'] != 'stopped':
                reciever = [audit.Auditor.email]
                subject = f'Completion of Vulnerability Scan for {audit.name}'
                message = render_template('audits/scan_complete_mail.html',server=os.getenv('SERVER_URL'), audit=audit, vulnerabilities=vulnerabilities)
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

    return render_template('audits/vulnerability.html', title=f'Vulnerabilities | {vulnerability_name}', audit=audit, vulnerability=eval(vulnerability.data), template=template)




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

    if 'cloud' in audit.asset_type:
        output = eval(output.cloud)
    
    vulnerabilities = VulnerabilityDiscovered.query \
        .join(VulnerabilityTemplates, VulnerabilityDiscovered.template_id == VulnerabilityTemplates.id) \
        .filter(VulnerabilityDiscovered.audit_id == audit.id).count()

    return render_template('audits/scan_result.html', title="Scan Results", audit=audit, output=output, vulnerabilities=vulnerabilities)



@audits.route('/audits/<string:audit_name>/verify')
@login_required
def scan_verify(audit_name):
    audit = Audit.query.filter_by(name=audit_name, Auditor=current_user).first()

    if not audit:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('audits.audit_list'))

    if audit.status == 'finished':
        audit.scan_verified = True
        db.session.commit()
        flash(f'Scan {audit_name} verified successfuly', 'success')
        return redirect(url_for('audits.vulnerabilities', audit_name=audit_name))
    
    flash(f'The audit {audit_name} has not been scanned yet.', 'info')
    return redirect(url_for('audits.vulnerabilities', audit_name=audit_name))