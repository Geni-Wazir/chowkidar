from flask import render_template,Blueprint, flash, redirect, url_for
from flask_login import current_user, login_required
from chowkidar.models import User, Audit, ScanResults, VulnerabilityDiscovered, VulnerabilityTemplates, CloudServices, CloudRegions, db
from chowkidar.audits.forms import WebUpdateAuditForm, CloudUpdateAuditForm
from chowkidar.admin.forms import TemplateForm
from chowkidar.audits.routes import initiate_scan
from chowkidar import limiter, task_queue
from chowkidar.utils.scheduler import delete_container, remove_task, run_scan
import os




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
    else:
        flash('Unfortunately, you do not have the privilege to access this audit', 'danger')
        return redirect(url_for('admin_view.all_audits'))
    return render_template('admin/update_audit.html', title="Admin", audit=audit, webform=webform, cloudform=cloudform, legend="Audit Insights")




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
                return redirect(url_for('admin_view.admin_audit', user_email=user_email, audit_name=audit_name))
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
            return redirect(url_for('admin_view.admin_audit', user_email=user_email, audit_name=audit_name))
        else:
            flash('Boost Your Scan with At Least One Cloud Service', 'info')
    else:
        # Handle form validation errors for cloud form
        errors = cloudform.errors.get('services')
        if errors:
            flash(", ".join(errors), 'info')

    return redirect(url_for('admin_view.admin_audit', user_email=user_email, audit_name=audit_name))




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
    
    try:
        initiate_scan(current_user, audit, 'scanning', db)
    except:
        flash(f'Error Initiating Scan for {audit.name}', 'danger')

    flash(f'Congratulations! Your {audit.name} scan has been successfully started.', 'success')
    return redirect(url_for('admin_view.all_audits'))




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

    return render_template('admin/vulnerability.html', title="Admin", audit=audit, vulnerability=eval(vulnerability.data), template=template)




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
    
    if 'cloud' in audit.asset_type:
        output = eval(output.cloud)
    
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




@admin_view.route('/admin/templates')
@login_required
def templates():
    if not current_user.admin:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('audits.audit_list'))
    templates = VulnerabilityTemplates.query.order_by(VulnerabilityTemplates.cvss.desc()).all()
    return render_template('admin/templates.html', title="Templates", templates=templates)




@admin_view.route('/admin/templates/new', methods=['GET', 'POST'])
@login_required
def add_template():
    if not current_user.admin:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('audits.audit_list'))

    form = TemplateForm()
    if form.validate_on_submit():
        template = VulnerabilityTemplates(
            name = form.name.data,
            description = form.description.data,
            impact = form.impact.data,
            severity = form.severity.data,
            steps = form.steps.data,
            fix = form.fix.data,
            cvss = form.cvss.data,
            cvss_string = form.cvss_string.data,
            cwe = form.cwe.data,
            type = form.type.data,
        )
        db.session.add(template)
        db.session.commit()
        flash('Updated', 'success')
    else:
        errors = list(form.errors.values())
        if errors:
            flash(", ".join(errors[0]), 'info')

    return render_template('admin/template.html', title="Templates", form=form)





@admin_view.route('/admin/templates/<string:template_name>', methods=['GET', 'POST'])
@login_required
def template(template_name):
    if not current_user.admin:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('audits.audit_list'))
    template = VulnerabilityTemplates.query.filter_by(name=template_name).first()
    if not template:
        flash('No template with this name found', 'danger')
        return redirect(url_for('admin_view.templates'))
    form = TemplateForm()
    if form.validate_on_submit():
        template.name = form.name.data
        template.description = form.description.data
        template.impact = form.impact.data
        template.severity = form.severity.data
        template.steps = form.steps.data
        template.fix = form.fix.data
        template.cvss = form.cvss.data
        template.cvss_string = form.cvss_string.data
        template.cwe = form.cwe.data
        template.type = form.type.data
        db.session.commit()
        flash('Successfuly updated the template', 'success')
        return redirect(url_for('admin_view.templates'))
    else:
        errors = list(form.errors.values())
        if errors:
            flash(", ".join(errors[0]), 'info')

    form.name.data = template.name
    form.description.data = template.description
    form.impact.data = template.impact
    form.severity.data = template.severity
    form.steps.data = template.steps
    form.fix.data = template.fix
    form.cvss.data = template.cvss
    form.cvss_string.data = template.cvss_string
    form.cwe.data = template.cwe
    form.type.data = template.type

    return render_template('admin/template.html', title="Templates", template=template, form=form)



@admin_view.route('/admin/templates/<string:template_name>/preview')
@login_required
def preview_template(template_name):
    if not current_user.admin:
        flash('Unfortunately, you do not have the privilege to access this', 'danger')
        return redirect(url_for('audits.audit_list'))
    template = VulnerabilityTemplates.query.filter_by(name=template_name).first()
    if not template:
        flash('No template with this name found', 'danger')
        return redirect(url_for('admin_view.templates'))
    return render_template('admin/vulnerability.html', title="Templates", template=template, audit='', vulnerability='')
