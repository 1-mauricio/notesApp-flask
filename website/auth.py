from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, logout_user, login_required, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user :
            if check_password_hash(user.password, password):
                flash('You have been logged in.', 'success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Please check your login details and try again.', category='error')
        else:
            flash('User dont exist', category='error')

    return render_template('login.html', text="testing", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        
        user = User.query.filter_by(email=email).first()

        if user:
            flash('User already exist', category='error')
            return render_template('sign-up.html')
        elif len(email) < 4:
            flash('Email is too short', category='error')
        elif len(first_name) < 2:
            flash('First name is too short', category='error')
        elif password1 != password2:
            flash('Passwords do not match', category='error')
        elif len(password1) < 7:
            flash('Password is too short', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash('User created', category='success')
            return redirect(url_for('auth.login'))
        
    return render_template('sign-up.html', user=current_user)