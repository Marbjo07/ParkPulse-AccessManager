from flask import Flask, redirect, url_for, request, render_template, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from access_manager import AccessManager, test_access_manager, performance_test_access_manager
import hashlib

# Initialize Flask app
app = Flask(__name__, static_folder="src")
app.secret_key = 'your_secret_key'
login_manager = LoginManager()
login_manager.init_app(app)

manager = AccessManager()

class User(UserMixin):
    def __init__(self, id):
        self.id = id

# User data
users = {
    'admin': {'password_hash': 'ac9edb5a26f3a2b0a7b93529812fbbdfab0fa95cd52a6f825edfbb0cd196086b', 'user_obj': User('admin')}
}

@login_manager.user_loader
def load_user(user_id):
    for user_name, user_data in users.items():
        if user_data['user_obj'].id == user_id:
            return user_data['user_obj']
    return None

@app.route("/")
def _():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_name = request.json['user_name']
        password = request.json['password']
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        user_data = users.get(user_name)
    
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
    return send_file('src/index.html'), 200

# Define routes
@app.route('/create_user', methods=['POST'])
def create_user():
    data = request.json
    user_name = data.get('user_name')
    password = data.get('password_hash')
    try:
        manager.create_user(user_name, password)
        return jsonify({"message": "User created successfully"}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
@app.route('/delete_user', methods=['POST'])
def delete_user():
    data = request.json
    user_name = data.get('user_name')
    success, error_message = manager.delete_user(user_name)
    if success:
        return jsonify({"message": "User deleted successfully"}), 201
    else:
        return jsonify({"error": error_message}), 400
    
@app.route('/list_users')
def list_users():
    all_users = manager.list_users()
    return jsonify({"message": all_users}), 200

@app.route('/create_group', methods=['POST'])
def create_group():
    data = request.json
    group_name = data.get('group_name')
    manager.create_group(group_name, {})
    return jsonify({"message": "Group created successfully"}), 201

@app.route('/add_user_to_group', methods=['POST'])
def add_user_to_group():
    data = request.json
    user_name = data.get('user_name')
    group_name = data.get('group_name')
    success, error_message = manager.add_user_to_group(user_name, group_name)
    if success:
        return jsonify({"message": "User added to group successfully"}), 201
    else:
        return jsonify({"error": error_message}), 400

@app.route('/authorize_request', methods=['POST'])
def authorize_request():
    data = request.json
    user_name = data.get('user_name')
    permission = tuple(data.get('permission'))
    try:
        authorized = manager.authorize_request(user_name, permission)
        return jsonify({"authorized": authorized}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route('/remove_user_from_group', methods=['POST'])
def remove_user_from_group():
    data = request.json
    user_name = data.get('user_name')
    group_name = data.get('group_name')
    try:
        manager.remove_user_from_group(user_name, group_name)
        return jsonify({"message": "User removed from group successfully"}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

@app.route('/authenticate_user', methods=['POST'])
def authenticate_user():
    data = request.json
    print(data)
    user_name = data.get('user_name')
    password_hash = data.get('password_hash')
    authenticated = manager.authenticate_user(user_name, password_hash)
    return jsonify({"authenticated": authenticated}), 200

@app.route('/run_tests')
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