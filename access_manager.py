import os
import sys
import time
import json
import random
import pickle
import logging
import functools
from typing import Dict, Tuple

# Define color codes
LOG_COLORS = {
    'DEBUG': '\033[94m',     # Blue
    'WARNING': '\033[93m',   # Yellow
    'ERROR': '\033[91m',     # Red
    'CRITICAL': '\033[95m',  # Magenta
    'RESET': '\033[0m'       # Reset
}

class ColoredFormatter(logging.Formatter):
    def format(self, record):
        log_color = LOG_COLORS.get(record.levelname, LOG_COLORS['RESET'])
        record.levelname = f"{log_color}{record.levelname}{LOG_COLORS['RESET']}"
        record.msg = f"{log_color}{record.msg}{LOG_COLORS['RESET']}"
        return super().format(record)


def setup_custom_logger(name):
    formatter = ColoredFormatter(fmt='[%(asctime)s.%(msecs)03d | %(levelname)s]: %(message)s',
                                  datefmt='%Y-%m-%d | %H:%M:%S')
    handler = logging.FileHandler('log.txt', mode='w')
    handler.setFormatter(formatter)
    screen_handler = logging.StreamHandler(stream=sys.stdout)
    screen_handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    logger.addHandler(screen_handler)
    return logger



# Organizes different accesses and premisions
class Group():
    def __init__(self, group_name:str, permissions:Dict[str, list[str]]) -> None:
        self.permissions: Dict[str, list[str]] = permissions
        self.group_name: str = group_name
        self.members: list[str] = []

    def is_allowed_access(self, request:Tuple[str, str]) -> bool:
        data_type, data_id = request

        if data_type not in self.permissions:
            return False

        permissions_for_data_type = self.permissions[data_type]
        return data_id in permissions_for_data_type
    
    def get_permission_as_string(self) -> str:
        string = ""
        for data_type in self.permissions:
            list_of_data_ids = ', '.join(self.permissions[data_type])
            string += f'"{data_type}": [{list_of_data_ids}] |'
        return string
    
    def count_permissions(self) -> dict[str, int]:
        num_data_ids_per_permission = {}
        for data_type in self.permissions:
            num_data_ids_per_permission.update({data_type:len(self.permissions[data_type])})
        return num_data_ids_per_permission
    
    def add_member(self, user_name:str) -> None:
        self.members.append(user_name)

    def remove_member(self, user_name:str) -> None:
        if user_name in self.members:
            self.members.remove(user_name)

    def add_permission(self, permission:Tuple[str, str]) -> None:
        data_type, data_id = permission
        # update existing data_type if it exist
        if data_type in self.permissions:
            if data_id not in self.permissions[data_type]:
                self.permissions[data_type].append(data_id)
        else:
            # create new data_type 
            new_permission = {data_type:[data_id]}
            self.permissions.update(new_permission)
    
    def remove_permission(self, permission:Tuple[str, str]) -> None:
        data_type, data_id = permission

        if data_type not in self.permissions:
            return

        if data_id not in self.permissions[data_type]:
            return
        
        self.permissions[data_type].remove(data_id)
        if len(self.permissions[data_type]) == 0:
            del self.permissions[data_type]

    def is_member(self, user_name:str) -> bool:
        return user_name in self.members
    
    def toJSON(self) -> str:
        return json.dumps({
            "group_name": self.group_name,
            "permissions": self.permissions
        })
    
class User():
    def __init__(self, user_name:str, password_hash:str) -> None:
        self.user_name: str = user_name
        self.password_hash: str = password_hash
        self.groups: list[str] = []

    def check_password(self, password_hash:str) -> bool:
        return self.password_hash == password_hash
    
    def join_group(self, group_name:str) -> None:
        self.groups.append(group_name)

    def quit_group(self, group_name:str) -> None:
        if group_name in self.groups:
            self.groups.remove(group_name)

    def in_group(self, group_name:str) -> bool:
        return group_name in self.groups
    
    def toJSON(self) -> str:
        return json.dumps({
            "user_name": self.user_name,
            "groups": self.groups,
        })            

class AccessManager():
    def __init__(self, state_file_path:str=None, load_state:bool=True, name:str="AccessManager", init_log_level=logging.INFO) -> None:
        self.users: Dict[str, User] = {}
        self.groups: Dict[str, Group] = {}

        self.logger = setup_custom_logger(name)
        self.set_logging_level(init_log_level)

        if state_file_path != None and load_state:
            self.load_state(state_file_path)
        
        self.state_file_path = state_file_path


    def save_state_after(method):
        @functools.wraps(method)
        def wrapper(self, *args, **kwargs):
            result = method(self, *args, **kwargs)
            if self.state_file_path != None:
                self.save_state(self.state_file_path)
            return result
        return wrapper

    @save_state_after
    def create_user(self, user_name:str, password_hash:str) -> Tuple[bool, str]:
        if self.user_exists(user_name):
            error_message = f'Tried to create existing user "{user_name}"'
            self.logger.error(error_message)
            return False, error_message
        new_user = User(user_name, password_hash)
 
        self.users.update({user_name: new_user})

        success_message = f'Created user "{user_name}".'
        self.logger.info(success_message)
        return True, success_message

    @save_state_after
    def delete_user(self, user_name:str) -> Tuple[bool, str]:
        if not self.user_exists(user_name):
            error_message = f'Tried to delete non-existent user "{user_name}"'
            self.logger.error(error_message)
            return False, error_message
        
        user = self.users[user_name]

        for group_name in user.groups:
            group = self.groups[group_name]

            if group.is_member(user_name):
                group.remove_member(user_name)

        del self.users[user_name]
        success_message = f'Deleted user "{user_name}".'
        self.logger.warning(success_message)
        return True, success_message
    
    
    @save_state_after
    def delete_group(self, group_name:str) -> Tuple[bool, str]:
        if not self.group_exists(group_name):
            error_message = f'Tried to delete non-existent group "{group_name}"'
            self.logger.error(error_message)
            return False, error_message
        
        group = self.groups[group_name]

        for user_name in group.members:
            user = self.users[user_name]
            # can quit non-joined groups
            user.quit_group(group_name)

        del self.groups[group_name]
        success_message = f'Deleted group "{user_name}".'
        self.logger.warning(success_message)
        return True, success_message
    
    def list_users(self) -> list[str]:
        self.logger.info(f'Listing all {len(self.users.keys())} users')
        users = list(self.users.values())
        users_json_dump = [user.toJSON() for user in users]
        return users_json_dump
    
    def list_user(self, user_name:str) -> Tuple[bool, str]:
        if not self.user_exists(user_name):
            error_message = f'Tried to list properties of non-existet user "{user_name}"'
            self.logger.warning(error_message)
            return False, error_message
        
        self.logger.info(f'Listing all properties of user "{user_name}"')
        user = self.users[user_name]

        users_json_dump = json.dumps({
            "user_name": user_name,
            "groups":[self.groups[group].toJSON() for group in user.groups]
        })

        return True, users_json_dump
    
    def list_group(self, group_name:str) -> Tuple[bool, str]:
        if not self.group_exists(group_name):
            error_message = f'Tried to list properties of non-existet group "{group_name}"'
            self.logger.warning(error_message)
            return False, error_message
        
        self.logger.info(f'Listing all properties of group "{group_name}"')
        group = self.groups[group_name]

        group_json_dump = json.dumps({
            "group_name": group_name,
            "members": group.members,
            "permissions": group.permissions
        })

        return True, group_json_dump
    
    def user_exists(self, user_name:str) -> bool:
        return user_name in self.users
    
    def group_exists(self, group_name:str) -> bool:
        return group_name in self.groups
    
    @save_state_after
    def create_group(self, group_name:str, permissions:Dict[str, list[str]]) -> None:
        if self.group_exists(group_name):
            self.logger.warning(f'Tried to create existing group "{group_name}"')
            return
        
        new_group = Group(group_name, permissions)

        self.groups.update({group_name: new_group })

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f'Created group "{group_name}". Permissions: {str(new_group.permissions)}')
        else:
            self.logger.info(f'Created group "{group_name}". Permissions: {new_group.count_permissions()}')

    @save_state_after
    def add_user_to_group(self, user_name:str, group_name:str) -> bool:
        if not self.user_exists(user_name):
            error_message = f'Tried to add non-existent user "{user_name}" to group {group_name}'
            self.logger.error(error_message)
            return False, error_message

        if not self.group_exists(group_name):
            error_message = f'Group "{group_name}" does not exist, could not add user "{user_name}"'
            self.logger.error(error_message)
            return False, error_message
        
        self.users[user_name].join_group(group_name)
        self.groups[group_name].add_member(user_name)

        success_message = f'Added user "{user_name}" to group "{group_name}"'
        self.logger.info(success_message)

        return True, success_message
    
    @save_state_after
    def add_permission_to_group(self, group_name:str, permission:Tuple[str, str]) -> Tuple[bool, str]:
        if not self.group_exists(group_name):
            error_message = f'Group "{group_name}" does not exist, could not add permission "{permission}"'
            self.logger.error(error_message)
            return False, error_message

        group = self.groups[group_name]

        if group.is_allowed_access(permission):
            error_message = f'Group "{group_name}" already has access to "{permission}"'
            self.logger.warning(error_message)
            return False, error_message

        group.add_permission(permission)

        success_message = f'Added permission "{permission}" to group "{group_name}"'
        self.logger.info(success_message)

        return True, success_message
    
    @save_state_after
    def remove_permission_from_group(self, group_name:str, permission:Tuple[str, str]) -> Tuple[bool, str]:
        if not self.group_exists(group_name):
            error_message = f'Group "{group_name}" does not exist, could not remove permission "{permission}"'
            self.logger.error(error_message)
            return False, error_message

        group = self.groups[group_name]
        # check if group even is allowed access
        if not group.is_allowed_access(permission):
            error_message = f'Group "{group_name}" does not have access to "{permission}"'
            self.logger.warning(error_message)
            return False, error_message
        
        group.remove_permission(permission)

        success_message = f'Removed permission "{permission}" from group "{group_name}"'
        self.logger.warning(success_message)

        return True, success_message
    
    @save_state_after
    def remove_user_from_group(self, user_name:str, group_name:str) -> Tuple[bool, str]:
        if not self.user_exists(user_name):
            error_message = f'Tried to remove non-existent user "{user_name}"'
            self.logger.error(error_message)
            return False, error_message

        if not self.group_exists(group_name):
            error_message = f'Tried to remove user "{user_name}" from non-existent group {group_name}'
            self.logger.error(error_message)
            return False, error_message
        
        user = self.users[user_name]
        group = self.groups[group_name]

        if not user.in_group(group_name):
            error_message = f'User {user_name} is not member of group {group_name}'
            self.logger.warning(error_message)
            return False, error_message
        
        if user.in_group(group_name) != group.is_member(user_name):
            error_message = f'Mismatch in user "{user_name}" and group "{group_name}" member data! User groups: "{user.groups}". Group members: "{group.members}"'
            self.logger.critical(error_message)
            return False, error_message
        
        self.groups[group_name].remove_member(user_name)
        self.users[user_name].groups.remove(group_name)

        success_message = f'Removed user "{user_name} from group "{group_name}"'
        self.logger.warning(success_message)
        return True, success_message

    def authorize_request(self, user_name:str, request:Tuple[str, str]) -> bool:
        data_type, data_id = request
        if not self.user_exists(user_name):
            self.logger.error(f'Tried to authorize request for non-existent user "{user_name}"')
            return False
        user = self.users[user_name]

        authorized = False
        for group_name in user.groups:
            if not self.group_exists(group_name):
                self.logger.error(f'User "{user_name}" is member of non-existent group "{group_name}"')  
                continue

            group = self.groups[group_name]

            if group.is_allowed_access(request):
                authorized = True
                self.logger.info(f'Group "{group_name}" authorized "{user_name}" to "{data_id}"')
                break

        if not authorized:
            self.logger.warning(f'User "{user_name}" tried to access "{data_id}"')

        return authorized
    
    def authenticate_user(self, user_name:str, password_hash:str) -> bool:
        if not self.user_exists(user_name):
            self.logger.warning(f'User "{user_name}" not found, unable to authenticate')
            return False

        if self.users[user_name].check_password(password_hash):
            self.logger.info(f'Authenticated user "{user_name}" with password hash "{password_hash}"')
            return True
        else:
            self.logger.warning(f'Authentication faild for user "{user_name}" with password hash "{password_hash}"')
            return False

    def set_logging_level(self, logging_level) -> None:
        self.logger.setLevel(logging_level)

    def is_user_in_group(self, user_name:str, group_name:str) -> bool:
        if not self.group_exists(group_name):
            self.logger.error(f'Group "{group_name}" does not exist therefore is user "{user_name}" not member')
            return False
        
        if not self.user_exists(user_name):
            self.logger.error(f'User "{user_name}" does not exists therefore is not in group "{group_name}"')
            return False
        
        group = self.groups[group_name]

        return group.is_member(user_name)
    
    def save_state(self, file_path: str) -> None:
        """Saves the current state of users and groups to a file."""
        try:
            with open(file_path, 'wb') as file:
                pickle.dump((self.users, self.groups), file)
            self.logger.debug(f'Successfully saved state to {file_path}')
        except Exception as e:
            self.logger.error(f'Failed to save state: {str(e)}')

    def load_state(self, file_path: str) -> None:
        """Loads the state of users and groups from a file."""
        try:
            if not os.path.exists(file_path):
                assert False, "File does not exist"

            with open(file_path, 'rb') as file:
                self.users, self.groups = pickle.load(file)
            self.logger.info(f'Successfully loaded state from {file_path}')
            self.logger.info(f'All users: {list(self.users.keys())}')
            self.logger.info(f'Total number of users: {len(self.users.keys())}')
            self.logger.info(f'All groups: {list(self.groups.keys())}')
            self.logger.info(f'Total number of groups: {len(self.groups.keys())}')
        except Exception as e:
            self.logger.critical(f'Failed to load state: {str(e)}')

    def delete_logger(self) -> None:
        self.logger.critical(f'Logger deletion called!')
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)


# Utility functions for colored text
def format_results(result, message, use_emoji=True):
    if use_emoji:
        emoji = "✅" if result else "❌"
    else:
        emoji = ""
    color = "green" if result else "red"
    return f'<div><span style="color:{color}" > {emoji} </span> <h4 style="display: inline;">{message}</h4> </div>'

# Test cases for AccessManager
def test_access_manager(debug:bool):
    manager = AccessManager(state_file_path="access_manager_test.state", load_state=False, name="AccessManagerTest")
    manager.set_logging_level(logging.DEBUG if debug else logging.CRITICAL)

    start_time = time.time()
    
    # Correct password hashes
    john_password_hash = "password1"
    jack_password_hash = "passwsord2"
    admin_password_hash ="password3"
    
    output = '<div style="display:flex;flex-wrap:wrap;align-content:center;flex-direction: column;">'
    # Test creating users
    try:
        manager.create_user("john", john_password_hash)
        manager.create_user("jack", jack_password_hash)
        manager.create_user("admin", admin_password_hash)
        output += format_results(True, "User creation test passed")
    except Exception as e:
        output += format_results(False, f"User creation test failed: {e}")

    # Verify that users are created
    output += format_results("john" in manager.users, "Verify 'john' exists")
    output += format_results("jack" in manager.users, "Verify 'jack' exists")
    output += format_results("admin" in manager.users, "Verify 'admin' exists")
    
    # Test creating groups with specific permissions
    
    manager.create_group("elaway-sweden", {'cities': ['stockholm', 'gothenburg', 'malmo']})
    if "elaway-sweden" in manager.groups:
        output += format_results(True, "Group creation test passed")
    else:
        output += format_results(False, f"Group creation test failed")
    
    # Verify group creation
    output += format_results("elaway-sweden" in manager.groups, "Verify 'elaway-sweden' group exists")
    output += format_results(manager.groups["elaway-sweden"].permissions == {'cities': ['stockholm', 'gothenburg', 'malmo']}, "Verify 'elaway-sweden' group permissions")
    
    # Test authorization requests before adding users to the group
    output += format_results(manager.authorize_request("john", ('cities', 'stockholm')) == False, "Authorization test before adding to group passed for 'john'")
    output += format_results(manager.authorize_request("jack", ('cities', 'stockholm')) == False, "Authorization test before adding to group passed for 'jack'")
    
    # Test adding users to the group
    success, message = manager.add_user_to_group("john", "elaway-sweden")
    if manager.is_user_in_group("john", "elaway-sweden"):
        output += format_results(True, "Add users to group test passed")
    else:
        output += format_results(False, f"Add users to group test failed: {message}")
    success, message = manager.add_user_to_group("jack", "elaway-sweden")
    if manager.is_user_in_group("jack", "elaway-sweden"):
        output += format_results(True, "Add users to group test passed")
    else:
        output += format_results(False, f"Add users to group test failed: {message}")
    # Verify that users are added to the group
    output += format_results(manager.is_user_in_group("john", "elaway-sweden"), "Verify 'john' added to 'elaway-sweden'")
    output += format_results(manager.is_user_in_group("jack", "elaway-sweden"), "Verify 'jack' added to 'elaway-sweden'")
    
    # Test authorization requests after adding users to the group
    output += format_results(manager.authorize_request("john", ('cities', 'stockholm')) == True, "Authorization test after adding to group passed for 'john'")
    output += format_results(manager.authorize_request("jack", ('cities', 'stockholm')) == True, "Authorization test after adding to group passed for 'jack'")
    output += format_results(manager.authorize_request("jack", ('cities', 'oslo')) == False, "Authorization test for invalid permission passed for 'jack'")
    
    # Test adding a user to a non-existent group
    manager.add_user_to_group("john", "non-existent-group")
    output += format_results(not manager.is_user_in_group("john", "non-existent-group"), "Add user to non-existent group should fail but passed")
    
    # Test adding a non-existent user to a group
    manager.add_user_to_group("non-existent-user", "elaway-sweden")
    output += format_results(not manager.is_user_in_group("non-existent-user", "elaway-sweden"), "Add non-existent user to group should fail but passed")
    
    
    # Test creating a group with overlapping permissions
    try:
        manager.create_group("elaway-norway", {'cities': ['oslo', 'bergen', 'trondheim']})
        output += format_results(True, "Create group with overlapping permissions test passed")
    except Exception as e:
        output += format_results(False, f"Create group with overlapping permissions test failed: {e}")
    
    # Verify group creation
    output += format_results("elaway-norway" in manager.groups, "Verify 'elaway-norway' group exists")
    output += format_results(manager.groups["elaway-norway"].permissions == {'cities': ['oslo', 'bergen', 'trondheim']}, "Verify 'elaway-norway' group permissions")
    
    # Test adding a user to multiple groups
    success, message = manager.add_user_to_group("john", "elaway-norway")
    if manager.is_user_in_group("john", "elaway-norway"):
        output += format_results(True, "Add user to multiple groups test passed")
    else:
        output += format_results(False, f"Add user to multiple groups test failed: {message}")
    
    # Verify that user is added to multiple groups
    output += format_results(manager.is_user_in_group("john", "elaway-norway"), "Verify 'john' added to 'elaway-norway'")
    
    # Test authorization requests after adding user to multiple groups
    output += format_results(manager.authorize_request("john", ('cities', 'oslo')) == True, "Authorization test for multiple groups passed for 'john'")
    output += format_results(manager.authorize_request("jack", ('cities', 'oslo')) == False, "Authorization test for invalid permission passed for 'jack'")
    
    # Test creating a user with an existing username
    manager.create_user("john", "newpassword")
    if manager.users["john"].check_password("newpassword"):
        output += format_results(False, "Create user with existing username should fail but passed")
    else:
        output += format_results(True, "Create user with existing username test passed")
    
    # Test authorizing request for non-existent user
    if manager.authorize_request("non-existent-user", ('cities', 'stockholm')):
        output += format_results(False, "Authorization for non-existent user should fail but passed")
    else:
        output += format_results(True, "Authorization for non-existent user test passed")
    
    # Test authorization for a non-existent permission
    authorized = manager.authorize_request("john", ('countries', 'sweden'))
    if authorized:
        output += format_results(False, "Authorization for non-existent permission should fail but passed")
    else:
        output += format_results(True, "Authorization for non-existent permission test passed")
    
    # Test removing user from group
    manager.remove_user_from_group("john", "elaway-sweden")
    if not manager.is_user_in_group("john", "elaway-sweden"):
        output += format_results(True, "Remove user from group test passed")
    else:
        output += format_results(False, f"Remove user from group test failed")

    # Verify that user is removed from the group
    output += format_results(not manager.is_user_in_group("john", "elaway-sweden"), "Verify 'john' removed from 'elaway-sweden'")
    output += format_results(manager.authorize_request("john", ('cities', 'stockholm')) == False, "Authorization test after removal from group passed for 'john'")
    
    # Test removing non-existent user from group
    manager.remove_user_from_group("non-existent-user", "elaway-sweden")
    if manager.is_user_in_group("non-existent-user", "elaway-sweden"):
        output += format_results(False, "Remove non-existent user from group should fail but passed")
    else:
        output += format_results(True, "Remove non-existent user from group test passed")

    # Test removing user from non-existent group
    manager.remove_user_from_group("john", "non-existent-group")
    if manager.is_user_in_group("john", "non-existent-group"):
        output += format_results(False, "Remove user from non-existent group should fail but passed")
    else:
        output += format_results(True, "Remove user from non-existent group test passed")

    # Test correct authentication
    output += format_results(manager.authenticate_user("john", john_password_hash), "Authentication passed for 'john' with correct password")
    output += format_results(manager.authenticate_user("jack", jack_password_hash), "Authentication passed for 'jack' with correct password")
    output += format_results(manager.authenticate_user("admin", admin_password_hash), "Authentication passed for 'admin' with correct password")

    # Test incorrect password
    output += format_results(not manager.authenticate_user("john", "wrongpasswordhash"), "Authentication failed for 'john' with incorrect password")
    output += format_results(not manager.authenticate_user("jack", "wrongpasswordhash"), "Authentication failed for 'jack' with incorrect password")
    output += format_results(not manager.authenticate_user("admin", "wrongpasswordhash"), "Authentication failed for 'admin' with incorrect password")

    # Test non-existent user
    output += format_results(not manager.authenticate_user("nonexistent", "passwordhash"), "Authentication failed for non-existent user")

    # Test empty username
    output += format_results(not manager.authenticate_user("", john_password_hash), "Authentication failed for empty username")

    # Test empty password
    output += format_results(not manager.authenticate_user("john", ""), "Authentication failed for empty password")

    # Test deleting an existing user
    success, message = manager.delete_user("john")
    if success:
        output += format_results(True, f"Delete existing user 'john' test passed: {message}")
    else:
        output += format_results(False, f"Delete existing user 'john' test failed")
    
    output += format_results("john" not in manager.users, "Verify 'john' is deleted")

    # Test deleting a non-existent user
    success, message = manager.delete_user("non-existent-user")
    if not success:
        output += format_results(True, f"Delete non-existent user test passed: {message}")
    else:
        output += format_results(False, f"Delete non-existent user test failed")

    # Test deleting a user and ensuring removal from groups
    
    manager.create_user("emma", "passord4")
    manager.add_user_to_group("emma", "elaway-sweden")
    success, message = manager.delete_user("emma")
    if success:
        output += format_results(True, f"Delete user 'emma' from group test passed: {message}")
    else:
        output += format_results(False, f"Delete user 'emma' from group test failed")

    output += format_results("emma" not in manager.users, "Verify 'emma' is deleted")
    output += format_results(not manager.is_user_in_group("emma", "elaway-sweden"), "Verify 'emma' is removed from 'elaway-sweden'")


    # Test authentication with a deleted user
    success = manager.authenticate_user("emma", "passord4")
    if not success:
        output += format_results(True, f"Authentication failed for deleted user")
    else:
        output += format_results(False, f"Deleted user emma authenticated")
    

    output += format_results(True, "All tests completed!", use_emoji=False)

    end_time = time.time()
    output += f"Tests complete in {end_time - start_time:f}s"
    output += "</div>"

    manager.delete_logger()
    return output

# Performance tests for AccessManager
def performance_test_access_manager(debug):
    
    performance_test_log_level = logging.INFO if debug else logging.CRITICAL
    manager = AccessManager(name="AccessManagerPerformanceTest")
    manager.set_logging_level(performance_test_log_level)

    output = ""

    num_users  = 10000
    num_groups = 10000
    num_cities = 10000
    num_reboots = 10

    # Performance test for creating users
    start_time = time.time()
    for i in range(num_users):
        manager.create_user(f"user{i}", f"password{i}")
    end_time = time.time()
    output += f"<h4>Time taken to create {num_users} users: {end_time - start_time:.4f} seconds</h4>"

    # Performance test for creating groups
    start_time = time.time()
    for i in range(num_groups):
        manager.create_group(f"group{i}", {'cities': ['city' + str(random.randint(0, num_cities)) for _ in range(int(num_cities ** 0.5))]})
    end_time = time.time()
    output += f"<h4>Time taken to create {num_groups} groups: {end_time - start_time:.4f} seconds</h4>"

    # Performance test for adding users to groups
    start_time = time.time()
    for i in range(num_users):
        manager.add_user_to_group(f"user{i}", f"group{i % num_groups}")
    end_time = time.time()
    output += f"<h4>Time taken to add {num_users} users to groups: {end_time - start_time:.4f} seconds</h4>"
    
    # Performance test for authorizing requests
    start_time = time.time()
    for i in range(num_users):
        manager.authorize_request(f"user{i}", ('cities', 'city0'))
    end_time = time.time()

    output += f"<h4>Time taken to authorize {num_users} requests: {end_time - start_time:.4f} seconds</h4>"

    manager.save_state("perf_test_save.state")
    # Performance test for rebooting
    start_time = time.time()
    for i in range(num_reboots):
        rebooted_manager = AccessManager(state_file_path="perf_test_save.state", name="AccessManagerPerformanceTest", init_log_level=performance_test_log_level)
        rebooted_manager.set_logging_level(performance_test_log_level)
        rebooted_manager.delete_logger()
        end_time = time.time()

    output += f"<h4>Time taken to reboot {num_reboots} times: {end_time - start_time:.4f} seconds</h4>"
    manager.delete_logger()
    return output

    
if __name__ == "__main__":

    test_access_manager()
    performance_test_access_manager()
    
    manager = AccessManager()
    manager.set_logging_level(logging.INFO)

    manager.create_user("john", "passord1")
    manager.create_user("jack", "passord2")
    manager.create_user("admin", "passord3")

    manager.create_group("elaway-sweden", {'cities': ['stockholm', 'gothenburg', 'malmo']})

    assert manager.authorize_request("john", ('cities','stockholm')) == False
    assert manager.authorize_request("jack", ('cities','stockholm')) == False
    
    manager.add_user_to_group("john", "elaway-sweden") 
    manager.add_user_to_group("jack", "elaway-sweden") 
    
    assert manager.authorize_request("john", ('cities', 'stockholm')) == True 
    assert manager.authorize_request("jack", ('cities','oslo')) == False 


    manager.set_logging_level(logging.WARN)


