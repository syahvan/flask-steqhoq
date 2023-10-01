from flask import Flask, render_template, request, jsonify, make_response, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_restful import Api, Resource, reqparse
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

# Membuat DataFrame dengan informasi karyawan
data = {
    'Divisi': ['IT', 'Sales', 'Marketing', 'Accounting'],
    'Jumlah Karyawan': [50, 25, 30, 20],
    'Rata-rata Gaji (juta Rupiah)': [8, 6, 7, 5]
}

df = pd.DataFrame(data)

app = Flask(__name__,template_folder='templates')
api = Api(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


class UserResource(Resource):
    def get(self, user_id):
        user = User.query.get(user_id)
        if not user:
            return {'message': 'User not found'}, 404
        return {'id': user.id, 'username': user.username}

    def put(self, user_id):
        user = User.query.get(user_id)
        if not user:
            return {'message': 'User not found'}, 404

        parser = reqparse.RequestParser()
        parser.add_argument('username', type=str, required=True)
        parser.add_argument('password', type=str, required=True)
        args = parser.parse_args()

        user.username = args['username']
        user.password = bcrypt.generate_password_hash(args['password']).decode('utf-8')
        db.session.commit()
        return {'message': 'User updated successfully'}

    def delete(self, user_id):
        user = User.query.get(user_id)
        if not user:
            return {'message': 'User not found'}, 404
        db.session.delete(user)
        db.session.commit()
        return {'message': 'User deleted successfully'}


api.add_resource(UserResource, '/user/<int:user_id>')


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))
    return render_template('login.html', form=form)



@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)



@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/karyawan')
@login_required
def karyawan():
    # Kode untuk menghasilkan grafik Jumlah Karyawan di Setiap Divisi
    plt.figure(figsize=(10, 5))
    plt.bar(df['Divisi'], df['Jumlah Karyawan'], color='skyblue')
    plt.xlabel('Divisi')
    plt.ylabel('Jumlah Karyawan')
    plt.title('Jumlah Karyawan di Setiap Divisi')
    plt.ticklabel_format(axis='y', style='plain')
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # Simpan grafik ke dalam file gambar
    plt.savefig('static/karyawan.png')
    
    return render_template('karyawan.html')


@app.route('/gaji')
@login_required
def gaji():
    # Kode untuk menghasilkan grafik Rata-rata Gaji Karyawan di Setiap Divisi
    plt.figure(figsize=(10, 5))
    plt.bar(df['Divisi'], df['Rata-rata Gaji (juta Rupiah)'], color='lightcoral')
    plt.xlabel('Divisi')
    plt.ylabel('Rata-rata Gaji (juta Rupiah)')
    plt.title('Rata-rata Gaji Karyawan di Setiap Divisi')
    plt.ticklabel_format(axis='y', style='plain')
    plt.grid(axis='y', linestyle='--', alpha=0.7)

    # Simpan grafik ke dalam file gambar
    plt.savefig('static/gaji.png')

    return render_template('gaji.html')


if __name__ == "__main__":
    app.run(debug=True)
