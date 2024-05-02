from flask import render_template,Blueprint
from flask_login import current_user, login_required
from chowkidar.models import Audit




audits = Blueprint('audits', __name__)



@audits.route('/audits')
@login_required
def all_audits():
    audits = Audit.query.filter_by(Auditor=current_user).order_by(Audit.id.desc())
    return render_template('audits/audits.html', title="Audits", audits=audits)
