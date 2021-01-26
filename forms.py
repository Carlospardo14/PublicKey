# Bibliotecas para los formularios y sus validaciones
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Email, Length

# Diferentes formularios utilizados en la aplicacion
class SignupForm(FlaskForm):
    name = StringField('Nombre: ', validators=[DataRequired(), Length(max=64)])
    password = PasswordField('Password :', validators=[DataRequired()])
    email = StringField('Email: ', validators=[DataRequired(), Email()])
    submit = SubmitField('Registrarse')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Recuérdame')
    submit = SubmitField('Login')

class CreateForm(FlaskForm):
    passphrase = PasswordField('PassPhrase', validators=[DataRequired()])
    submit = SubmitField('Crear')

class DownloadForm(FlaskForm):
    submit = SubmitField('Descargar')

class AuthForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()] )