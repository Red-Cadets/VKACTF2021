from flask import Flask, session, redirect, url_for, request, render_template, abort, jsonify
from flask_login import LoginManager, UserMixin, login_required,login_user, current_user,logout_user
from flask_sqlalchemy import SQLAlchemy
from json import loads, dumps
from random import randint
from flask_migrate import *
from flask import *
from werkzeug.security import *
from json import dumps, loads

from project.models import db, User
from project import app, login_manager

flag = app.config['FLAG']

p = ???

def generate(x, a, b):
    next_x = (x * a + b) % p
    return next_x

@app.route('/',methods=['post','get'])
def start():
    if request.method == 'POST':
        if 'sign_button' in request.form:
            return redirect(url_for('sign'))
        elif 'login_button' in request.form:
            return redirect(url_for('login'))
    return render_template("index.html")

@app.route('/sign', methods=['post','get'])
def sign():
    if request.method == 'POST':
        if db.session.query(User).filter_by(username = request.form.get('username')).all():
            return render_template('sign.html', error="Пользователь с таким именем уже есть")
        u = User(username = request.form.get('username'), a = randint(1,p-1), b = randint(1,p-1), seed = randint(1,p-1) )
        u.set_password(request.form.get('password'))
        db.session.add(u)
        db.session.commit()
        login_user(u)
        return redirect(url_for('lottery'))
    return render_template('sign.html')


@app.route('/login',methods=['post','get'])
def login():
    if request.method == 'POST':
        user = db.session.query(User).filter(User.username == request.form.get('username')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user)
            return redirect(url_for('lottery'))
        else:
            return render_template('login.html', error="Неверный пароль/логин")
    return render_template('login.html')

@app.route('/lottery',methods=['post','get'])
def lottery():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    user = current_user
    seed = user.seed
    next_x = seed
    mass = []
    result = []
    for i in range(12):
        next_x = generate( next_x , user.a, user.b)
        mass.append(next_x)
    mass_user = []
    numbers = []
    attempts = 0
    success = None
    if user.test:
        numbers = loads(user.test)
        attempts = len(numbers) // 4
        for i in range(attempts):
            l = []
            for j in range(4):
                l.append({"input":numbers[i * 4 + j], "correct":mass[i * 4 + j]})
            result.append(l)
        
    if request.method == 'POST':
        if attempts < 3:
            for i in range(4):
                try:
                    userinput = int(request.form.get('lot_{}'.format(i + 1)))
                    assert  userinput >= 0
                except:
                    error = "Вводимые значения должны быть положительные числа"
                    return render_template('lot.html', test = attempts, result = result, error = error)
                
                mass_user.append(userinput)
        else:
            return render_template('lot.html', test = attempts, result = result, error = "Попыток больше нет!")
        l = []
        if mass_user == mass[attempts * 4: (attempts+1) * 4]:
            success = flag
        for i in range(4):
            l.append({"input":mass_user[i], "correct":mass[attempts * 4 + i]})
        result.append(l)
        user.test = dumps(numbers + mass_user)
        db.session.add(user)
        db.session.commit()
        return render_template('lot.html', test = attempts + 1, result = result, success = success)
    return render_template('lot.html', test = attempts, result=result)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)