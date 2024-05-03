from flask_wtf import FlaskForm
from wtforms import SubmitField, BooleanField




class UpdateAuditForm(FlaskForm):
    nmap = BooleanField('Nmap Scan', default=True)
    headers = BooleanField('Security Header Scan', default=True)
    dirsearch = BooleanField('Directory Scan', default=True)
    testssl = BooleanField('TLS/SSL Scan', default=True)
    nuclei = BooleanField('Nuclei Scan', default=False)
    sublister = BooleanField('Subdomain Scan', default=False)
    wpscan = BooleanField('Wordpress Scan', default=False)
    submit = SubmitField('Add Audit')