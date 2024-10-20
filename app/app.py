from flask import Flask, redirect, url_for, request, render_template, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user

from access_manager import AccessManager, test_access_manager, performance_test_access_manager
import os
import sys
import signal
import hashlib
import logging
import secrets

# Initialize Flask app
app = Flask(__name__, static_folder="src", template_folder="src")
app.secret_key = secrets.token_urlsafe(32)

login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin):
    def __init__(self, id):
        self.id = id

DEFUALT_PASSWORD_HASH = "998ed4d621742d0c2d85ed84173db569afa194d4597686cae947324aa58ab4bb"
admin_password_hash =  os.getenv("ADMIN_PASSWORD_HASH", DEFUALT_PASSWORD_HASH)
if admin_password_hash == DEFUALT_PASSWORD_HASH:
    print("WARNING: admin password not configured")

# User data
users = {
    'admin': {'password_hash': admin_password_hash, 'user_obj': User('admin')}
}

FRONTEND_URL = os.environ['FRONTEND_URL']
BACKEND_SERVER_URL = os.environ['BACKEND_SERVER_URL']
ACCESS_MANAGER_URL = os.environ['ACCESS_MANAGER_URL']

if os.environ['FLASK_ENV'] == "development":
    app.config['PROPAGATE_EXCEPTIONS'] = True
    
manager = AccessManager(state_file_path='access_manager.state', 
                        backend_server_url=BACKEND_SERVER_URL, 
                        frontend_url=FRONTEND_URL, 
                        init_log_level=logging.DEBUG if app.debug else logging.DEBUG)

@login_manager.user_loader
def load_user(user_id):
    for username, user_data in users.items():
        if user_data['user_obj'].id == user_id:
            return user_data['user_obj']
    return None

# used to start up server before expection of soon user request
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    manager.logger.info("recived ping!")
    return 'ok'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.json['username']
        password = request.json['password']
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        user_data = users.get(username)
    
        if user_data and user_data['password_hash'] == password_hash:
            login_user(user_data['user_obj'])

            return redirect(url_for('control_panel'))
        
        return jsonify({'error': 'Invalid credentials'}), 401
    
    return send_file('src/login/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out'

@app.route('/control_panel')
@login_required
def control_panel():
    return render_template('index.html', access_manager_url=ACCESS_MANAGER_URL), 200

@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
    data = request.json
    username = data.get('username')
    password = data.get('passwordHash') # treat passwordHash as password
    
    success, message = manager.create_user(username, password)
    if success:
        return jsonify({"message": message}), 201
    else:
        return jsonify({"error": message}), 400
    
@app.route('/setup_onboarding', methods=['POST'])
@login_required
def setup_onboarding():
    data = request.json
    username = data.get('username')
    
    # it restarts the proccess if user already exists
    success, setup_auth_str, message = manager.setup_onboarding(username)
    if success:
        onboarding_link = manager.create_setup_link_from_auth_str(username, setup_auth_str)
        return jsonify({"message": onboarding_link}), 201
    else:
        return jsonify({"error": message}), 400

    
@app.route('/finish_onboarding', methods=['POST'])
def finish_onboarding():
    data = request.json
    username = data.get('username')
    password = data.get('passwordHash')
    setup_auth_str = data.get('token')

    print(data)
    success, message = manager.finish_onboarding(username, password, setup_auth_str)
    if success:
        return jsonify({"message": message}), 201
    else:
        return jsonify({"error": message}), 400 

@app.route('/disable_user_session', methods=['POST'])
@login_required
def disable_user_session():
    data = request.json
    username = data.get('username')
    success, error_message = manager.disable_user_session(username)
    if success:
        return jsonify({"message": "Disabled user session successfully"}), 201
    else:
        return jsonify({"error": error_message}), 400
    
@app.route('/delete_user', methods=['POST'])
@login_required
def delete_user():
    data = request.json
    username = data.get('username')
    success, error_message = manager.delete_user(username)
    if success:
        return jsonify({"message": "User deleted successfully"}), 201
    else:
        return jsonify({"error": error_message}), 400
    
@app.route('/request_password_reset', methods=['POST'])
def request_password_reset():
    data = request.json
    
    if 'username' not in data:
        return jsonify({'error': 'Invalid request, must provide username'}), 400
    
    username = data['username']

    success, response = manager.reset_user_password(username)
    return jsonify({'message': 'If an account with that email exists, you will receive a password reset email shortly.'}), 200

@app.route('/list_user', methods=["POST"])
@login_required
def list_user():
    data = request.json
    username = data.get('username')
    success, error_message_or_user = manager.list_user(username)
    if success:
        return jsonify({"message": f"Listed all properties of user {username}", "user": error_message_or_user}), 200
    else:
        return jsonify({"error": error_message_or_user}), 400
    
@app.route('/list_available_cities', methods=["POST"])
def list_available_cities():
    data = request.json

    if 'username' not in data:
        return jsonify({'error': 'Invalid request, must provide username'}), 400
    
    username = data['username']

    success, error_message_or_user = manager.list_user_cities(username)
    if success:
        return jsonify({"message": f"Listed all available cities for user {username}", "cities": error_message_or_user}), 200
    else:
        return jsonify({"error": error_message_or_user}), 400

@app.route('/list_group', methods=["POST"])
@login_required
def list_group():
    data = request.json

    if 'group_name' not in data:
        return jsonify({'error': 'Invalid request, must provide group_name'}), 400
    
    group_name = data['group_name']
    success, error_message_or_group = manager.list_group(group_name)
    if success:
        return jsonify({"message": f"Listed all properties of group {group_name}", "group": error_message_or_group}), 200
    else:
        return jsonify({"error": error_message_or_group}), 400

@app.route('/create_group', methods=['POST'])
@login_required
def create_group():
    data = request.json
    group_name = data.get('group_name')
    success, response = manager.create_group(group_name, {})
    if success:
        return jsonify({"message": f"Created group {group_name}"}), 201
    else:
        return jsonify({"error": response}), 400

@app.route('/add_user_to_group', methods=['POST'])
@login_required
def add_user_to_group():
    data = request.json
    username = data.get('username')
    group_name = data.get('group_name')
    success, message = manager.add_user_to_group(username, group_name)
    if success:
        return jsonify({"message": message}), 201
    else:
        return jsonify({"error": message}), 400
    
@app.route('/add_permissions_to_group', methods=['POST'])
@login_required
def add_permission_to_group():
    data = request.json
    group_name = data.get('group_name')
    data_type = data.get('dataType')
    data_ids = data.get('dataIds')

    if "," in data_ids:
        data_ids = data_ids.split(",")
    else:
        data_ids = [data_ids]
    for data_id in data_ids:
        success, message = manager.add_permission_to_group(group_name, (data_type, data_id.strip()))
    if success:
        return jsonify({"message": message}), 201
    else:
        return jsonify({"error": message}), 400
    
@app.route('/remove_permissions_from_group', methods=['POST'])
@login_required
def remove_permissions_from_group():
    data = request.json
    group_name = data.get('group_name')
    data_type = data.get('dataType')
    data_ids = data.get('dataIds')
    
    if "," in data_ids:
        data_ids = data_ids.split(",")
    else:
        data_ids = [data_ids]
    for data_id in data_ids:
        success, message = manager.remove_permission_from_group(group_name, (data_type, data_id.strip()))
    if success:
        return jsonify({"message": message}), 201
    else:
        return jsonify({"error": message}), 400

@app.route('/authorize_request', methods=['POST'])
def authorize_request():
    data = request.json
    username = data.get('username')
    permission = tuple(data.get('request'))
    
    authorized = manager.authorize_request(username, permission)
    if authorized:
        return jsonify({"authorized": True}), 200
    else:
        return jsonify({"authorized": False}), 401

@app.route('/authenticate_user', methods=['POST'])
def authenticate_user():
    data = request.json
    username = data.get('username')
    password_hash = data.get('passwordHash')

    authenticated, auth_hash, isDev = manager.authenticate_user(username, password_hash)
    allowed_resources = manager.list_allowed_resources_for_user(username)

    if not authenticated:
        return jsonify({"authenticated": False, "isDev":False,  "allowedDataSource": []}), 401
    
    return jsonify({"authenticated": True, "auth_hash":auth_hash, "isDev":isDev, "allowedDataSource": allowed_resources}), 200

@app.route('/remove_user_from_group', methods=['POST'])
@login_required
def remove_user_from_group():
    data = request.json
    username = data.get('username')
    group_name = data.get('group_name')
    success, message = manager.remove_user_from_group(username, group_name)
    if success:
        return jsonify({"message": message}), 201
    else:
        return jsonify({"error": message}), 400

@app.route('/delete_group', methods=['POST'])
@login_required
def delete_group():
    data = request.json
    group_name = data.get('group_name')
    success, message = manager.delete_group(group_name)
    if success:
        return jsonify({"message": message}), 201
    else:
        return jsonify({"error": message}), 400


def handle_sigterm(*args):
    print("Received SIGTERM, shutting down gracefully...")
    sys.exit(0)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_sigterm)
    if os.environ['FLASK_ENV'] == 'production':
        app.run(app)
    else:
        app.run(app, debug=True)