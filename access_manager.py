import logging
import sys
from typing import Dict, Tuple
import time
import random

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

        assert data_type in self.permissions, f'data_type "{data_type}" not in self.permissions "{self.permissions}"'

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
        self.members.remove(user_name)

    def is_member(self, user_name:str) -> bool:
        return user_name in self.members
            
class User():
    def __init__(self, user_name:str, password_hash:str) -> None:
        self.user_name: str = user_name
        self.password_hash: str = password_hash
        self.groups: list[Group] = []

    def check_password(self, password_hash:str) -> bool:
        return self.password_hash == password_hash
    
    def join_group(self, group_name:str) -> None:
        self.groups.append(group_name)

    def is_in_group(self, group_name:str) -> bool:
        return group_name in self.groups
            
        
class AccessManager():
    def __init__(self, name:str="AccessManager") -> None:
        self.users: Dict[str, User] = {}
        self.groups: Dict[str, Group] = {}

        self.logger = setup_custom_logger(name)

    def create_user(self, user_name:str, password_hash:str) -> None:
        if user_name in self.users:
            self.logger.error(f'Tried to create existing user "{user_name}"')
            return
        new_user = User(user_name, password_hash)

        self.users.update({user_name: new_user})
        self.logger.info(f'Created user "{user_name}".')

    def delete_user(self, user_name:str) -> bool:
        if user_name not in self.users:
            error_message = f'Tried to delete non-existent user "{user_name}"'
            self.logger.error(error_message)
            return False, error_message
        
        for group_name in self.users[user_name].groups:
            group = self.groups[group_name]

            if group.is_member(user_name):
                group.remove_member(user_name)

        del self.users[user_name]

        return True, ""
    
    def list_users(self) -> list[str]:
        self.logger.info(f'listing all {len(self.users.keys())} users')
        user_strings = []
        for user_name in self.users.keys():
            user = self.users[user_name]

            user_string = user_name + " | " +  str(user.groups)
            user_strings.append(user_string)

        return user_strings
            
    
    def create_group(self, group_name:str, permissions:Dict[str, list[str]]) -> None:
        new_group = Group(group_name, permissions)

        self.groups.update({group_name: new_group })

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f'Created group "{group_name}". Permissions: {str(new_group.permissions)}')
        else:
            self.logger.info(f'Created group "{group_name}". Permissions: {new_group.count_permissions()}')

    def add_user_to_group(self, user_name:str, group_name:str) -> bool:
        if group_name not in self.groups:
            error_message = f'Group "{group_name}" does not exist'
            self.logger.error(error_message)
            return False, error_message
        
        self.users[user_name].join_group(group_name)
        self.groups[group_name].add_member(user_name+"1")
        self.logger.info(f'Added user "{user_name}" to group "{group_name}"')

        return True, ""
    
    def remove_user_from_group(self, user_name:str, group_name:str) -> None:
        if user_name not in self.users:
            self.logger.error(f'Tried to remove non-existent user "{user_name}"')
            return

        if group_name not in self.groups:
            self.logger.error(f'Tried to remove user "{user_name}" from non-existent group {group_name}')
            return
        
        user = self.users[user_name]
        group = self.groups[group_name]

        if not user.is_in_group(group_name):
            self.logger.warning(f'User {user_name} is not member of group {group_name}')
            return
        
        if user.is_in_group(group_name) != group.is_member(user_name):
            self.logger.critical(f'Mismatch in user "{user_name}" and group "{group_name}" member data! User groups: "{user.groups}". Group members: "{group.members}"')
            return 
        
        self.groups[group_name].remove_member(user_name)
        self.users[user_name].groups.remove(group_name)

    def authorize_request(self, user_name:str, request:Tuple[str, str]):
        data_type, data_id = request
        if user_name not in self.users:
            self.logger.error(f'Tried to authorize request for non-existent user "{user_name}"')
            return False
        user = self.users[user_name]

        authorized = False
        for group_name in user.groups:
            if group_name not in self.groups:
                self.logger.error(f'User "{user_name}" is member of non-existent group "{group_name}"')  
                continue

            group = self.groups[group_name]

            # catch assertion thrown in group, missing data_type
            try:
                is_allowed_access = group.is_allowed_access(request)
            except AssertionError:
                self.logger.error(f'data_type "{data_type}" not found in group')
                continue

            if is_allowed_access:
                authorized = True
                self.logger.info(f'Group "{group_name}" authorized "{user_name}" to "{data_id}"')
                break

        if not authorized:
            self.logger.warning(f'User "{user_name}" tried to access "{data_id}"')

        return authorized
    
    def authenticate_user(self, user_name:str, password_hash:str) -> bool:
        if user_name not in self.users:
            self.logger.warning(f'User "{user_name}" not found, unable to authenticate')
            return False

        if self.users[user_name].check_password(password_hash):
            self.logger.info(f'Authenticated user "{user_name}" with password hash "{password_hash}"')
            return True
        else:
            self.logger.warning(f'Authentication faild for user "{user_name}"')
            return False

    def set_logging_level(self, logging_level) -> None:
        self.logger.setLevel(logging_level)

    def is_user_in_group(self, user_name:str, group_name:str) -> bool:
        if group_name not in self.groups:
            self.logger.error(f'Group "{group_name}" does not exist therefore is user "{user_name}" not member')
            return False
        
        group = self.groups[group_name]

        return group.is_member(user_name)
    

# Utility functions for colored text
def format_results(result, message, use_emoji=True):
    if use_emoji:
        emoji = "✅" if result else "❌"
    else:
        emoji = ""
    color = "green" if result else "red"
    return f'<span style="color:{color}" > {emoji} </span> <h4 style="display: inline;">{message}</h4> <br>'

# Test cases for AccessManager
def test_access_manager(debug:bool):
    manager = AccessManager(name="AccessManagerTest")
    manager.set_logging_level(logging.DEBUG if debug else logging.CRITICAL)

    start_time = time.time()
    
    # Correct password hashes
    john_password_hash = "password1"
    jack_password_hash = "passwsord2"
    admin_password_hash ="password3"
    
    output = ""
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
    try:
        manager.add_user_to_group("john", "elaway-sweden")
        manager.add_user_to_group("jack", "elaway-sweden")
        output += format_results(True, "Add users to group test passed")
    except Exception as e:
        output += format_results(False, f"Add users to group test failed: {e}")
    
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
    try:
        manager.add_user_to_group("john", "elaway-norway")
        output += format_results(True, "Add user to multiple groups test passed")
    except Exception as e:
        output += format_results(False, f"Add user to multiple groups test failed: {e}")
    
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

    output += format_results(True, "All tests completed!", use_emoji=False)

    end_time = time.time()
    output += f"Tests complete in {end_time - start_time:f}s"
    for handler in manager.logger.handlers[:]:
        manager.logger.removeHandler(handler)
    return output

# Performance tests for AccessManager
def performance_test_access_manager(debug):
    manager = AccessManager(name="AccessManagerPerformanceTest")
    manager.set_logging_level(logging.INFO if debug else logging.CRITICAL)

    output = ""

    num_users  = 10000
    num_groups = 10000
    num_cities = 10000
    
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
    for handler in manager.logger.handlers[:]:
        manager.logger.removeHandler(handler)
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


