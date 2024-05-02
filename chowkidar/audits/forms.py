from flask_wtf import FlaskForm
from flask_login import current_user
from wtforms import StringField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, ValidationError, URL
from chowkidar.models import Audit



class AuditForm(FlaskForm):
    name = StringField('Project Name', validators=[DataRequired(), Length(min=3, max=100)])
    url = StringField('Scoup URL', validators=[DataRequired(), Length(max=100), URL(message="Looks like the URL provided is invalid.")])
    nmap = BooleanField('Port Scan', default=True)
    headers = BooleanField('Security Header Scan', default=True)
    dirsearch = BooleanField('Directory Scan', default=True)
    testssl = BooleanField('TLS/SSL Scan', default=True)
    nuclei = BooleanField('Nuclei Scan', default=False)
    sublister = BooleanField('Subdomain Scan', default=False)
    wpscan = BooleanField('Wordpress Scan', default=False)
    submit = SubmitField('Add Audit')


    def validate_name(self, name):
        excluded_chars = " _*?!`'^+%&/()=}][{$#"
        for char in self.name.data:
            if char in excluded_chars:
                raise ValidationError('Project names should only contain letters and hyphens "-"')
        audit = Audit.query.filter_by(name=name.data.lower(), Auditor=current_user).first()
        if audit:
            raise ValidationError('Project with this name already exist.')
        if self.name.data == 'new':
            raise ValidationError('The project name cannot be set as new')



class UpdateAuditForm(FlaskForm):
    nmap = BooleanField('Nmap Scan', default=True)
    headers = BooleanField('Security Header Scan', default=True)
    dirsearch = BooleanField('Directory Scan', default=True)
    testssl = BooleanField('TLS/SSL Scan', default=True)
    nuclei = BooleanField('Nuclei Scan', default=False)
    sublister = BooleanField('Subdomain Scan', default=False)
    wpscan = BooleanField('Wordpress Scan', default=False)
    submit = SubmitField('Add Audit')
