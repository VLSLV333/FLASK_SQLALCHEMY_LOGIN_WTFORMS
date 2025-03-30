from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text,ForeignKey
from functools import wraps
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from typing import List

from forms import CreatePostForm, RegisterNewUserForm, LoginUserForm, CommentForm

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # ----- added for performance boost reason
ckeditor = CKEditor(app)
Bootstrap5(app)

#create Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = None
app.config['SESSION_PERMANENT'] = False


# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# class-Table to store user data + manage login\logout session
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id: Mapped[int] = mapped_column(Integer, unique=True, primary_key=True, nullable=False)
    name: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)

    #tables-relationship code - as Parent
    posts: Mapped[List["BlogPost"]] = relationship(back_populates="author")
    comments: Mapped[List["Comment"]] = relationship(back_populates="author")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


# Table to store blogPosts info
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    #tables-relationship code - as Child
    author_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    author: Mapped["User"] = relationship(back_populates="posts")

    # tables-relationship code - as Parent
    comments: Mapped[List["Comment"]] = relationship(back_populates="post")

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, unique=True, nullable=False)
    text: Mapped[str] = mapped_column(String(250), nullable=False)

    #tables-relationship code - as Child
    author_id: Mapped[int] = mapped_column(ForeignKey("user.id"), nullable=False)
    author: Mapped["User"] = relationship(back_populates="comments")

    post_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"), nullable=False)
    post: Mapped["BlogPost"] = relationship(back_populates="comments")



#created this decorator to check if users are admins
def admin_only(func):
    @wraps(func)
    def check_if_user_admin(*args, **kwargs):
        if current_user.id != 1:
            abort(403)
        return func(*args, **kwargs)
    return check_if_user_admin


# Callback to reload the user object from the user ID stored in the session
@login_manager.user_loader
def load_user(user_id):
    return db.session.execute(db.select(User).where(User.id == user_id)).scalar()

with app.app_context():
    db.create_all()

@app.route('/register',methods=['GET','POST'])
def register():
    register_form = RegisterNewUserForm()
    if request.method == 'POST' and register_form.validate_on_submit():
        user_name = register_form.user_name.data
        user_email = register_form.user_email.data
        user_password = generate_password_hash(register_form.user_password.data,method='pbkdf2:sha256',salt_length=12)
        try:
            new_user = User(name=user_name, email=user_email,password=user_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=False)
            return redirect(url_for('get_all_posts'))

        except IntegrityError as e:
            db.session.reset()
            cause_of_error = str(e).split('(sqlite3.IntegrityError) UNIQUE constraint failed: ')[1].split('\n')[0]
            if cause_of_error == 'user.email':
                register_form.user_email.errors.append("This email is already registered. Please use a different email.")
            elif cause_of_error == 'user.name':
                register_form.user_name.errors.append("This name is already registered. Please use a different name.")
            return render_template("register.html", form=register_form)
    return render_template("register.html",form=register_form)


@app.route('/login',methods=['GET','POST'])
def login():
    login_form = LoginUserForm()
    if request.method == 'POST' and login_form.validate_on_submit():
        user_email = login_form.user_email.data
        user_password = login_form.user_password.data

        user_to_login = db.session.execute(db.select(User).where(User.email == user_email)).scalar()
        if user_to_login is None:
            login_form.user_email.errors.append("User with this email does not exist")
            return render_template("login.html", form=login_form)

        hashed_pass = user_to_login.password

        if check_password_hash(hashed_pass, user_password):
            login_user(user_to_login,remember=False)  # ---------- This way we will be logged out if user completely closes browser
            return redirect(url_for('get_all_posts'))
        else:
            login_form.user_password.errors.append("Wrong password")
            return render_template("login.html", form=login_form)

    return render_template("login.html", form=login_form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


@app.route("/post/<int:post_id>", methods=['GET','POST'])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if request.method == 'POST' and form.validate_on_submit():
        comment_text=form.body.data.split('<p>')[1].split('</p>')[0]
        new_comment = Comment(text=comment_text,author_id=current_user.id,post_id=post_id)
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post',post_id=post_id))

    return render_template("post.html", post=requested_post,form=form)


@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=False)
