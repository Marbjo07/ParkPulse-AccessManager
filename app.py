from flask import Flask, redirect, url_for, request, render_template, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from access_manager import AccessManager, test_access_manager, performance_test_access_manager
import hashlib
import os
import requests

# Initialize Flask app
app = Flask(__name__, static_folder="src", template_folder="src")
app.secret_key = '1a05ccb9f2e670310e129ef67b1a05ccb9f2e670310e129ef67b67b1a05ccb929a0bf3'
login_manager = LoginManager()
login_manager.init_app(app)

if app.debug:
    ACCESS_MANAGER_LOCATION = "http://127.0.0.1:5050"
    BACKEND_SERVER_LOCATION = "http://127.0.0.1:5000"
    FRONTEND_LOCATION = "http://127.0.0.1:5500"
else:
    ACCESS_MANAGER_LOCATION = "https://parkpulse-accessmanager.azurewebsites.net"
    BACKEND_SERVER_LOCATION = "https://parkpulse-api.azurewebsites.net"
    FRONTEND_LOCATION = "https://parkpulse-web.azurewebsites.net"

import logging
manager = AccessManager(state_file_path='access_manager.state', 
                        backend_server_location=BACKEND_SERVER_LOCATION, 
                        frontend_location=FRONTEND_LOCATION, 
                        localdev=app.debug,
                        init_log_level=logging.INFO if app.debug else logging.DEBUG)


class User(UserMixin):
    def __init__(self, id):
        self.id = id

# User data
users = {
    'admin': {'password_hash': 'ac9edb5a26f3a2b0a7b93529812fbbdfab0fa95cd52a6f825edfbb0cd196086b', 'user_obj': User('admin')}
}

@login_manager.user_loader
def load_user(user_id):
    for username, user_data in users.items():
        if user_data['user_obj'].id == user_id:
            return user_data['user_obj']
    return None

@app.route("/")
def _():
    return redirect(url_for('login'))


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
        
        return 'Invalid credentials'
    
    return send_file('src/login/login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out'

@app.route('/control_panel')
@login_required
def control_panel():
    return render_template('index.html', access_manager_location=ACCESS_MANAGER_LOCATION), 200

@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
    data = request.json
    username = data.get('username')
    password = data.get('password_hash') # treat password_hash as password

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
    success, message, setup_auth_str = manager.setup_onboarding(username)
    if success:
        return jsonify({"message": message, "setup_auth_str": setup_auth_str}), 201
    else:
        return jsonify({"error": message}), 400

    
@app.route('/finish_onboarding', methods=['POST'])
def finish_onboarding():
    data = request.json
    username = data.get('username')
    password = data.get('password_hash')
    setup_auth_str = data.get('token')


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
    manager.create_group(group_name, {})

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
    data_type = data.get('data_type')
    data_ids = data.get('data_ids')

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
    data_type = data.get('data_type')
    data_ids = data.get('data_ids')
    
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
    password_hash = data.get('password_hash')

    authenticated, auth_hash, has_sword = manager.authenticate_user(username, password_hash)

    if not authenticated:
        return jsonify({"authenticated": False, "has_sword":False}), 401
    
    return jsonify({"authenticated": True, "auth_hash":auth_hash, "has_sword":has_sword}), 201

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

@app.route('/run_manager_test')
@login_required
def run_tests():
    debug = request.args.get("debug")=="True"
    if debug:
        manager.logger.warning(f'---------------- starting test ----------------')
    output = test_access_manager(debug)
    if debug:    
        manager.logger.warning(f'---------------- test complete ----------------')
    return output

running_perf_tests = False
@app.route('/run_perf_tests')
@login_required
def run_perf_tests():
    global running_perf_tests
    if running_perf_tests:
        return jsonify({"error":"Wait until previous performance test is done!"}), 429
    else:
        running_perf_tests = True

    debug = request.args.get("debug")=="True"
    if debug:
        manager.logger.warning(f'---------------- starting test ----------------')
    output = performance_test_access_manager(debug)
    if debug:    
        manager.logger.warning(f'---------------- test complete ----------------')
    running_perf_tests = False
    return output

# Run the app
if __name__ == '__main__':
    app.run(debug=True, port=5050)