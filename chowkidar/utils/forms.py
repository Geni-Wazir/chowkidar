from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email




class WPSapiForm(FlaskForm):
    api_key = StringField('API key', validators=[DataRequired(), Length(min=40, max=50)])
    submit = SubmitField('Update')



class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=3, max=100)])
    email = StringField('Email Address', validators=[DataRequired(), Length(max=100), Email()])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Connect')