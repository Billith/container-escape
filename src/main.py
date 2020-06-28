from flask import Flask, render_template, request, session, redirect, url_for
from flask import abort, jsonify, flash
from flask_bcrypt import Bcrypt
from functools import wraps
import threading
import datetime
import secrets
import docker
import os

from database import db_session
from models.user import User
import utils


app = Flask(__name__)
app.config['BCRYPT_LOG_ROUNDS'] = 12
app.secret_key = secrets.token_bytes(32)
bcrypt = Bcrypt(app)

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


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if session.get('is_admin') and session['is_admin']:
            return func(*args, **kwargs)
        else:
            return redirect(url_for('index'))
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
    session.clear()
    return redirect('/')


@app.route('/users', methods=['GET'])
@login_required
@admin_required
def users():
    # It's ugly af, but if I import it in the global namespace, then import loop
    # is created, because models/user.py imports app and db objects from main.
    # At least it works.
    from models.user import User
    return render_template(
        'users.html',
        is_logged_in=session.get('login'),
        is_admin=session.get('is_admin'),
        users=User.query.all()
    )


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

    if 'id' in session and session['id'].split('-')[0] == challenge:
        try:
            client.containers.get(session['id'])  # check if container exists
            container_name = session['id']             # required by template
        except:
            session.pop('id', None)
            return redirect(url_for('challenge_page', challenge=challenge))
    else:
        session['id'] = challenge + '-' + utils.generate_id() + '-' + session['login']
        container_name = session['id']  # required by template

    return render_template(
        f'{challenge}.html',
        container_name=container_name,
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
        challenge_id = session['id'].split('-')[1]
        username = ''.join(session['id'].split('-')[2:])

        if challenge in enabled_challenges and not utils.container_exists(client, session['id']):
            if utils.check_user_container_limit(client, username):
                return jsonify(message='error', reason='Challenge instances limit reached')
            try:
                threading.Thread(
                    target=enabled_challenges[challenge].run_instance,
                    args=(session['id'], keepalive_containers)
                ).start()
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
                threading.Thread(
                    target=enabled_challenges[challenge].run_instance,
                    args=(session['id'], keepalive_containers)
                ).start()
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


@app.route('/api/users/create', methods=['POST'])
@login_required
@admin_required
def create_user():
    data = request.get_json()
    user_login = data['login']
    password = data['password']

    if not 8 <= len(password) <= 72:
        return jsonify(message='error'), 400

    from models.user import User
    if User.query.filter(User.login == user_login).first() is None:
        pw_hash = bcrypt.generate_password_hash(password)
        user = User(user_login, pw_hash, False)
        db_session.add(user)
        db_session.commit()
        return jsonify(message='ok'), 200

    return jsonify(message='error'), 400


@app.route('/api/users/delete/<int:user_id>', methods=['GET'])
@login_required
@admin_required
def dalete_user(user_id):
    from models.user import User
    user = User.query.filter(User.id == user_id).first()
    if user:
        db_session.delete(user)
        db_session.commit()
        return jsonify(message='ok'), 200

    return jsonify(message='error'), 400

# This function will automatically remove database sessions at the end of the 
# request or when the application shuts down
@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()


if __name__ == '__main__':
    utils.setup_logger()
    utils.check_privs()
    utils.load_challenges(enabled_challenges, client, solved_challenges)
    utils.build_challenges(enabled_challenges)
    utils.init_database(bcrypt)
    threading.Thread(
        target=utils.remove_orphans,
        args=(client, keepalive_containers, enabled_challenges)
    ).start()
    app.run(host='127.0.0.1')
