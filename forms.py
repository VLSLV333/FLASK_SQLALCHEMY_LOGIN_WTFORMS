from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, IntegerField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField

# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterNewUserForm(FlaskForm):
    user_name = StringField("Name", validators=[DataRequired()])
    user_email = EmailField("Email", validators=[DataRequired(),Email()])
    user_password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Register")


class LoginUserForm(FlaskForm):
    user_email = EmailField("Email", validators=[DataRequired(),Email()])
    user_password = StringField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class CommentForm(FlaskForm):
    body = CKEditorField("Write your comment", validators=[DataRequired()])
    submit = SubmitField("Create comment")