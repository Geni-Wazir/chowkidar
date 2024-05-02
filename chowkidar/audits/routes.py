from flask import render_template,Blueprint, flash, redirect, url_for
from flask_login import current_user, login_required
from chowkidar.models import Audit, db
from chowkidar.audits.forms import AuditForm




audits = Blueprint('audits', __name__)



@audits.route('/audits')
@login_required
def audit_list():
    audits = Audit.query.filter_by(Auditor=current_user).order_by(Audit.id.desc())
    return render_template('audits/audits.html', title="Audits", audits=audits)




@audits.route('/audits/new', methods=['GET', 'POST'])
@login_required
def add_audit():
    form = AuditForm()
    if form.validate_on_submit():
        if current_user.scan_available:
            if any(list(form.data.values())[2:-1]):
                audit = Audit(
                            name=form.name.data.lower(),
                            url=form.url.data,
                            nmap=form.nmap.data,
                            dirsearch=form.dirsearch.data,
                            headers=form.headers.data,
                            testssl=form.testssl.data,
                            nuclei=form.nuclei.data,
                            sublister=form.sublister.data,
                            wpscan=form.wpscan.data,
                            Auditor=current_user
                            )
                db.session.add(audit)
                db.session.commit()
                flash('Audit has been Added to Your Universe', 'success')
                return redirect(url_for('audits.audit_list'))
            else:
                flash('Boost Your Scan with at Least One Empowering Tool', 'info')
        else:
            flash('Your Scan Count is Low! Connect with Admin for Additional Scans', 'info')
            return redirect(url_for('audits.audit_list'))
    elif list(form.errors.values()) != []:
        flash(", ".join(list(form.errors.values())[0]), 'info')
    return render_template('audits/add_audit.html', title="Add Audit", form=form, legend="New Audit")

