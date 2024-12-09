from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo


class TicketForm(FlaskForm):
    title = StringField('title', validators=[DataRequired(), Length(max=255)])
    description = TextAreaField('description', validators=[DataRequired()])
    category = SelectField('category', coerce=int)
    priority = SelectField('priority', coerce=int)
    submit = SubmitField('Create Ticket')


class UpdateTicketForm(FlaskForm):
    title = StringField('title', validators=[DataRequired(), Length(max=255)])
    description = TextAreaField('description', validators=[DataRequired()])
    category = SelectField('category', coerce=int)
    priority = SelectField('priority', coerce=int)
    submit = SubmitField('Update Ticket')


class UpdateStatusForm(FlaskForm):
    status = SelectField('status', coerce=int)
    submit = SubmitField('Save')


class CommentForm(FlaskForm):
    content = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Add Comment')


class RegisterForm(FlaskForm):
    username = StringField('username', validators=[DataRequired(), Length(min=3, max=20)])
    email = StringField('email', validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def __init__(self, *args, **kwargs):
        super(RegisterForm, self).__init__(*args, **kwargs)


class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Length(1, 64), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    remember_me = BooleanField('remember')
    submit = SubmitField('login')

    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)

