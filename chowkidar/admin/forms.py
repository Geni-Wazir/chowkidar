from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField, TextAreaField, DecimalField
from wtforms.validators import DataRequired, Length, ValidationError
from chowkidar.models import VulnerabilityTemplates



class TemplateForm(FlaskForm):
    name = StringField('Vulnerability Name', validators=[DataRequired(), Length(min=3, max=100)])
    description = TextAreaField('Description')
    impact = TextAreaField('Impact')
    severity = SelectField('Role', choices=[('CRITICAL', 'CRITICAL'), ('HIGH', 'HIGH'),('MEDIUM', 'MEDIUM'),('LOW', 'LOW'),('INFO', 'INFO')])
    steps = TextAreaField('Steps')
    fix = TextAreaField('Fixes')
    cvss = DecimalField('CVSS', places=1)
    cvss_string = StringField('CVSS String')
    cwe = StringField('CWE')
    type = StringField('Template Type')
    submit = SubmitField('Add template')

    def validate_name(self, name):
        excluded_chars = "?!`'^+%/=}][{$#"
        for char in self.name.data:
            if char in excluded_chars:
                raise ValidationError('Template names should only contain letters and hyphens "-"')
        if self.name.data == 'new':
            raise ValidationError('The Template name cannot be set as new')
