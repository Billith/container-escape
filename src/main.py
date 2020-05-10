from flask import Flask, render_template, request, session, redirect, url_for
from flask import abort, jsonify, flash
from flask_bcrypt import Bcrypt
from functools import wraps
import threading
import datetime
import logging
import secrets
import docker
import os

from models.user import User
import utils


app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['BCRYPT_LOG_ROUNDS'] = 14
app.secret_key = secrets.token_bytes(32)

app.logger.setLevel(logging.DEBUG)
formatter = app.logger.handlers[0].formatter
handler = logging.FileHandler('/var/log/sandbox-escape.log')
handler.setFormatter(formatter)
app.logger.addHandler(handler)

client = docker.from_env()
keepalive_containers = {}
solved_challenges = []
enabled_challenges = {}


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if session.get('login'):
            return func(*args, **kwargs)
        else:
            return redirect(url_for('login'))
    return wrapper


@app.route('/', methods=['GET'])
def index():
    return render_template(
        'index.html',
        is_logged_in=session.get('login'),
        is_admin=session.get('is_admin')
    )


@app.route('/login', methods=['GET', 'POST'])
def login():
    # already authenticated user
    if session.get('login'):
        return redirect('/')

    # user that tries to login
    if request.method == 'POST':
        login = request.values.get('login')
        password = request.values.get('password')
        user = utils.auth(bcrypt, login, password)
        if user:
            session['login'] = user.login
            session['is_admin'] = user.is_admin
            return redirect('/')
        else:
            flash('Wrong login or password')
            return render_template('login.html')
    elif request.method == 'GET':
        return render_template('login.html')


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    del session['login']
    del session['is_admin']
    return redirect('/')


@app.route('/challenges', methods=['GET'])
def challenges_page():
    return render_template(
        'challenges.html',
        challenges=enabled_challenges,
        is_logged_in=session.get('login'),
        is_admin=session.get('is_admin')
    )


@app.route('/challenges/<challenge>', methods=['GET'])
@login_required
def challenge_page(challenge):
    if challenge not in enabled_challenges:
        abort(404)

    if 'id' not in session:
        random_id = challenge + '-' + utils.generate_id()
        session['id'] = random_id
    else:
        try:
            client.containers.get(session['id'])
            random_id = session['id']
        except:
            session.clear()
            return redirect(url_for('challenge_page', challenge=challenge))

    return render_template(
        f"{challenge}.html",
        user_id=random_id,
        is_logged_in=session.get('login'),
        is_admin=session.get('is_admin')
    )


@app.route('/api/container/keepalive', methods=['GET'])
@login_required
def keepalive_container():
    global keepalive_containers

    if 'id' in session:
        container_name = session['id']
        keepalive_containers[container_name] = datetime.datetime.now()
        app.logger.info(f'updated keepalive for {container_name}')
        return jsonify(message='ok'), 200

    return jsonify(message='wrong format'), 400


@app.route('/api/container/run', methods=['GET'])
@login_required
def run_container():
    if 'id' in session:
        challenge = session['id'].split('-')[0]

        if challenge in enabled_challenges:
            try:
                threading.Thread(target=enabled_challenges[challenge].run_instance, args=(session['id'],)).start()
                return jsonify(message='ok'), 200
            except Exception as e:
                app.logger.error(e)

    return jsonify(message='error'), 400


@app.route('/api/container/revert', methods=['GET'])
@login_required
def revert_container():
    if 'id' in session:
        challenge = session['id'].split('-')[0]

        if challenge in enabled_challenges:
            try:
                enabled_challenges[challenge].remove_instance(session['id'])
                threading.Thread(target=enabled_challenges[challenge].run_instance, args=(session['id'],)).start()
                return jsonify(message='ok'), 200
            except Exception as e:
                app.logger.error(e)

    return jsonify(message='error'), 400


@app.route('/api/container/status', methods=['GET'])
@login_required
def container_status():
    if 'id' in session:
        if session['id'] in solved_challenges:
            return jsonify(message='solved'), 200
        else:
            return jsonify(message='not solved'), 200

    return jsonify(message='error'), 400


if __name__ == '__main__':
    utils.check_privs()
    utils.load_challenges(enabled_challenges, client, solved_challenges)
    utils.build_challenges(enabled_challenges)
    utils.init_database(bcrypt)
    threading.Thread(target=utils.remove_orphans, args=(client, keepalive_containers, enabled_challenges)).start()
    app.run(host='127.0.0.1')
