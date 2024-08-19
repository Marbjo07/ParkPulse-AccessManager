import os
import sys
import time
import json
import random
import pickle
import hashlib
import logging
import secrets
import requests
import functools
from typing import Dict, Tuple
from azure.storage.blob import BlobServiceClient
from azure.identity import DefaultAzureCredential
from azure.communication.email import EmailClient

LOG_LEVEL_SWORD = 1000
POLLER_WAIT_TIME = 10

# Define color codes
LOG_COLORS = {
    'DEBUG': '\033[94m',     # Blue
    'WARNING': '\033[93m',   # Yellow
    'ERROR': '\033[91m',     # Red
    'CRITICAL': '\033[95m',  # Magenta
    f'Level {LOG_LEVEL_SWORD}': '\033[42m',
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
    
    def add_member(self, username:str) -> None:
        self.members.append(username)

    def remove_member(self, username:str) -> None:
        if username in self.members:
            self.members.remove(username)

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

    def is_member(self, username:str) -> bool:
        return username in self.members
    
    def toJSON(self) -> str:
        return json.dumps({
            "group_name": self.group_name,
            "permissions": self.permissions
        })
    
class User():
    def __init__(self, username:str, password_hash:str|None=None, setup_auth_hash:str|None=None) -> None:
        self.username: str = username
        self.password_hash: str = password_hash
        self.groups: list[str] = []
        self.setup_complete = False if password_hash == None else True
        
        self.online:bool = False
        self.setup_auth_hash: str = setup_auth_hash
        self.is_resetting_password = True

    def check_password(self, password_hash:str) -> bool:
        return self.password_hash == password_hash
    
    def join_group(self, group_name:str) -> None:
        self.groups.append(group_name)

    def quit_group(self, group_name:str) -> None:
        if group_name in self.groups:
            self.groups.remove(group_name)

    def in_group(self, group_name:str) -> bool:
        return group_name in self.groups

    def start_password_reset(self) -> None:
        self.is_resetting_password = True

    def finish_setup(self, password_hash:str, setup_auth_str:str) -> Tuple[bool, str]:
        if not self.setup_complete or self.is_resetting_password:
            verfication_hash = hashlib.sha256((self.username + setup_auth_str).encode()).hexdigest()
            if verfication_hash != self.setup_auth_hash:
                return False, "verfication failed"
            
            self.password_hash = password_hash
            self.setup_complete = True
            self.is_resetting_password = False
            return True, "success"
        else:
            return False, "setup is already completed"
    
    def in_session(self) -> bool:
        return self.online

    def new_session(self) -> str:
        self.session_auth_str = secrets.token_hex(32)
        self.online = True
        auth_hash = hashlib.sha256(self.session_auth_str.encode()).hexdigest()
        return auth_hash 
    
    def end_session(self) -> str:
        if self.online:
            auth_str = str(self.session_auth_str)
            self.session_auth_str = None
            self.online = False
            return auth_str
        else:
            return None

    def toJSON(self) -> str:
        return json.dumps({
            "username": self.username,
            "groups": self.groups,
        })            

class AccessManager():
    def __init__(self, backend_server_url:str=None, frontend_url:str=None, state_file_path:str=None, load_state:bool=True, name:str="AccessManager", init_log_level=logging.DEBUG) -> None:
        self.users: Dict[str, User] = {}
        self.groups: Dict[str, Group] = {}

        self.logger = setup_custom_logger(name)
        self.set_logging_level(init_log_level)

        self.use_azure_storage = os.getenv('USE_AZURE_STORAGE', 'False') == 'True'
        self.azure_blob_service_url = os.getenv('AZURE_BLOB_SERVICE_URL', '')
        self.azure_container_name = os.getenv('AZURE_CONTAINER_NAME', '')

        self.backend_server_url = backend_server_url
        self.frontend_url = frontend_url

        if self.use_azure_storage:
            credential = DefaultAzureCredential()
            self.blob_service_client = BlobServiceClient(account_url=self.azure_blob_service_url, credential=credential)
            

        if state_file_path is not None and load_state:
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
    def create_user(self, username:str, password:str|None=None, setup_auth_hash:str|None=None) -> Tuple[bool, str]:
        if self.user_exists(username):
            error_message = f'Tried to create existing user "{username}"'
            self.logger.error(error_message)
            return False, error_message
        
        if password == None:

            if setup_auth_hash == None:
                error_message = f'Must pass setup_auth_hash for empty user "{username}"'
                self.logger.critical(error_message)
                return False, error_message
            
            self.logger.info(f'Creating empty user "{username}"')
            new_user = User(username, setup_auth_hash=setup_auth_hash)
        else: 
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            new_user = User(username, password_hash)

 
        self.users.update({username: new_user})

        success_message = f'Created user "{username}"'
        self.logger.info(success_message)
        return True, success_message

    @save_state_after
    def delete_user(self, username:str) -> Tuple[bool, str]:
        if not self.user_exists(username):
            error_message = f'Tried to delete non-existent user "{username}"'
            self.logger.error(error_message)
            return False, error_message
        
        user = self.users[username]

        self.disable_user_session(username)

        for group_name in user.groups:
            group = self.groups[group_name]

            if group.is_member(username):
                group.remove_member(username)

        del self.users[username]
        success_message = f'Deleted user "{username}".'
        self.logger.warning(success_message)

        return True, success_message
    
    @save_state_after
    def disable_user_session(self, username:str) -> Tuple[bool, str]:
        self.logger.info(f'Disabling session for user "{username}"')

        if not self.user_exists(username):
            error_message = f'User "{username}" doest not exist, cant disable user session'
            self.logger.warning(error_message)
            return False, error_message
        
        user = self.users[username]
        if not user.in_session():
            error_message = f'User "{username}" is not online, cant disable session'
            self.logger.warning(error_message)
            return False, error_message

        auth_str = user.end_session()
        
        data = json.loads(json.dumps({'username': username, 'auth_str':auth_str}))

        url = f'{self.backend_server_url}/disable_user_session'
        response = requests.post(url=url, json=data)

        if response.status_code != 200:
            self.logger.error(f'Unabled to disabled session for user "{username}": {response.json()}')
            return False, response.json()
            
        self.logger.info(f'Successfully disabled session for user "{username}"')
        return True, response.json()

    @save_state_after
    def setup_onboarding(self, username:str, is_resetting_password:bool=False) -> Tuple[bool, str, str]:
        self.logger.info(f'Setting up onboarding for user "{username}", is resetting password: "{is_resetting_password}"')

        setup_auth_str = secrets.token_hex(32)

        setup_auth_hash = hashlib.sha256((username + setup_auth_str).encode()).hexdigest()
        
        # save password 
        if is_resetting_password:
            if not self.user_exists(username):
                error_message = f'Tried to save password_hash of non-existent user "{username}"'
                self.logger.critical(error_message)
                return False, "", error_message

            password_hash = self.users[username].password_hash
            self.users[username].start_password_reset()

        # restart onboarding proccess
        joined_groups = None
        if self.user_exists(username):
            self.logger.warning(f'Restarting onboarding proccess for user "{username}"')

            user = self.users[username]
            # copy joined groups
            joined_groups = user.groups.copy()

            # delete user
            success, message = self.delete_user(username)

            # undefined behaviour            
            if not success:
                self.logger.critical(f"Error occurred when restarting onboarding proccess: {message}")
        
        success, message = self.create_user(username, setup_auth_hash=setup_auth_hash)
        if not success:
            return False, "", message
        
        # insert saved password
        if is_resetting_password:
            self.logger.info(f"Setting password hash {password_hash[:10]}")
            self.users[username].password_hash = password_hash

        # join previously joined groups
        if joined_groups:
            user = self.users[username]

            for group_name in joined_groups:
                success, message = self.add_user_to_group(username, group_name)

                # undefined behaviour
                if not success:
                    self.logger.critical(f'User "{username}" unable to rejoin group {group_name}, error: {message}')

        success_message = f'Onboarding token created'
        self.logger.info(success_message)
        return True, setup_auth_str, success_message
    
    @save_state_after
    def finish_onboarding(self, username:str, password:str, setup_auth_str:str) -> Tuple[bool, str]:
        self.logger.info(f'Finishing onboarding for user "{username}"')

        if not self.user_exists(username):
            error_message = f'User "{username}" does not exist, could not finish onboarding'
            self.logger.error(error_message)
            return False, error_message
        
        user = self.users[username]

        password_hash = hashlib.sha256((password).encode()).hexdigest()

        success, message = user.finish_setup(password_hash, setup_auth_str)
        if not success:
            error_message = f'Faild to setup user "{username}", error: {message}'
            self.logger.error(error_message)
            return False, error_message
        
        success_message = f'Setup complete for user "{username}"'
        self.logger.info(success_message)
        return True, success_message

    @save_state_after
    def delete_group(self, group_name:str) -> Tuple[bool, str]:
        self.logger.info(f'Deleting group "{group_name}"')

        if not self.group_exists(group_name):
            error_message = f'Tried to delete non-existent group "{group_name}"'
            self.logger.error(error_message)
            return False, error_message
        
        group = self.groups[group_name]

        for username in group.members:
            user = self.users[username]
            # can quit non-joined groups
            user.quit_group(group_name)

        del self.groups[group_name]
        success_message = f'Deleted group "{group_name}".'
        self.logger.warning(success_message)
        return True, success_message
    
    def send_slack_notification(self, message:str) -> Tuple[bool, str]:
        self.logger.info(f'Sending slack notification "{message[:10]}...{message[-10:]}"')

        SLACK_WEBHOOK_URL = os.environ['SLACK_WEBHOOK_URL']

        data = {
            'text': message
        }

        response = requests.post(SLACK_WEBHOOK_URL, json=data)

        if response.status_code != 200:
            error_message = f"Request to Slack returned an error {response.status_code}, the response is:\n{response.text}"
            self.logger.critical(error_message)
            return False, error_message

        success_message = f'Successfully notfiyed Bob, he\'s now nagging about: "{message}"' 
        return True, success_message 

    # username is actually an email
    def get_name_from_username(self, username:str) -> str:
        self.logger.debug(f'Getting user\'s name from username "{username}"')
        
        name = username.split("@")[0]
        self.logger.debug(f'Name: "{name}"')
        
        name = name.replace('.', ' ')
        self.logger.debug(f'Name: "{name}"')

        name = name.title()
        self.logger.debug(f'Name: "{name}"')

        return name

    def send_password_reset_email(self, username:str, password_reset_link:str) -> Tuple[bool, str]:
        recipient_name = self.get_name_from_username(username)

        try:
            # fill template
            message = {
                "content": {
                    "subject": "Password Reset Request",
                    "plainText": f"""
Hi {recipient_name},

There was a request to change your password!

If you did not make this request then please ignore this email.

Otherwise, please click this link to change your password: {password_reset_link}
""",
                },
                "recipients": {
                    "to": [
                        {
                            "address": username,
                            "displayName": recipient_name
                        }
                    ]
                },
                "senderAddress": os.environ['EMAIL_SENDER_ADDRESS']
            }

            # create email client and send 
            email_client = EmailClient.from_connection_string(os.environ['CONNECTION_STRING'])
            poller = email_client.begin_send(message)

            # wait for email status
            time_elapsed = 0
            while not poller.done():
                self.logger.debug("Email send poller status: " + poller.status())

                poller.wait(POLLER_WAIT_TIME)
                time_elapsed += POLLER_WAIT_TIME

                if time_elapsed > 18 * POLLER_WAIT_TIME:
                    raise RuntimeError("Polling timed out.")

            if poller.result()["status"] == "Succeeded":
                self.logger.info(f"email sent (operation id: {poller.result()['id']})")
            else:
                raise RuntimeError(str(poller.result()["error"]))

        except Exception as ex:
            self.logger.error(ex)
            error_message = f'Faild to send password reset email to "{username}"'
            self.logger.error(error_message)
            return error_message, False
        
        success_message = f'Successfully sent password reset email to "{username}"' 
        self.logger.info(success_message)
        return success_message, True

    def create_setup_link_from_auth_str(self, username:str, setup_auth_str:str) -> str:
        #http://127.0.0.1:5500/signup?email=marius.bjorhei@gmail.com&token=1
        link = f'{self.frontend_url}/signup?email={username}&token={setup_auth_str}'
        self.logger.info(f'Created setup link for user "{username}"')
        return link
    
    def reset_user_password(self, username:str) -> Tuple[bool, str]:
        self.logger.info(f'Starting password reset for user "{username}"')

        if not self.user_exists(username):
            self.logger.error(f'Tried to reset password for non-existent user "{username}"')
            sent_slack_message, response = self.send_slack_notification(f'TF unknown user "{username}" wanted to reset their password?')

            if not sent_slack_message:
                self.logger.critical(f'Faild to notify of admin of password reset error')

            return False, "user does not exists"

        reset_user_password_success, setup_auth_str, _ = self.setup_onboarding(username, is_resetting_password=True)
        
        if not reset_user_password_success:
            error_message = f'Unable to reset password for user "{username}"'
            self.logger.critical(error_message)
            return False, "unable to reset user password"

        password_reset_link = self.create_setup_link_from_auth_str(username, setup_auth_str)

        sent_email_success, response = self.send_password_reset_email(username, password_reset_link) 

        # notify admin with email status, username and link
        slack_message = f'hey, i saw that "{username}" wanted to reset their password. Could you give them this link? "{password_reset_link}"'
        slack_message += " | Email Status: "
        slack_message += "Sent" if sent_email_success else f"{response}"

        sent_slack_message, response = self.send_slack_notification(slack_message)
        
        if not sent_slack_message:
            error_message = f'Unable to notify Bob about password reset for user "{username}"'
            self.logger.critical(error_message)  
            return False, "unable to send notification"
        
        # logging
        success_message = f'Successfully completed password reset for user "{username}" and notified Bob'
        self.logger.info(success_message) 
        return True, success_message

    def list_users(self) -> list[str]:
        self.logger.info(f'Listing all {len(self.users.keys())} users')
        users = list(self.users.values())
        users_json_dump = [user.toJSON() for user in users]
        return users_json_dump
    
    def list_user(self, username:str) -> Tuple[bool, str]:
        if not self.user_exists(username):
            error_message = f'Tried to list properties of non-existet user "{username}"'
            self.logger.warning(error_message)
            return False, error_message
        
        self.logger.info(f'Listing all properties of user "{username}"')
        user = self.users[username]

        users_json_dump = json.dumps({
            "username": username,
            "groups":[self.groups[group].toJSON() for group in user.groups],
            "online": user.online,
            "setup_complete": user.setup_complete
        })

        return True, users_json_dump
    
    def is_user_all_powerful(self, username:str) -> bool:
        if not self.user_exists(username):
            return False
        
        if self.is_user_in_group(username, "Seraphim"):
            self.logger.log(LOG_LEVEL_SWORD, f'User "{username}" used his sword!')
            return True
        
        return False

    def list_user_cities(self, username:str) -> Tuple[bool, str]:
        if not self.user_exists(username):
            error_message = f'Tried to list all cities for non-existet user "{username}"'
            self.logger.warning(error_message)
            return False, error_message
        
        self.logger.info(f'Listing all available cities for user "{username}"')
        user = self.users[username]
        
        # Determine which groups to check based on the user's power level
        if self.is_user_all_powerful(username): 
            groups_to_check = self.groups
        else:
            groups_to_check = {name: self.groups[name] for name in user.groups}

        # Iterate over the groups and collect available cities from permissions
        available_cities = []
        for group in groups_to_check.values():
            if 'city' in group.permissions:
                available_cities += group.permissions['city']

        self.logger.info(f'All available cities for user "{username}": {available_cities}')
        return True, available_cities
    
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
    
    def user_exists(self, username:str) -> bool:
        return username in self.users
    
    def group_exists(self, group_name:str) -> bool:
        return group_name in self.groups
    
    @save_state_after
    def create_group(self, group_name:str, permissions:Dict[str, list[str]]) -> Tuple[bool, str]:
        self.logger.info(f'Creating group "{group_name}"')

        if self.group_exists(group_name):
            error_message = f'Tried to create existing group "{group_name}"'
            self.logger.warning(error_message)
            return False, error_message
        
        new_group = Group(group_name, permissions)

        self.groups.update({group_name: new_group })

        if self.logger.isEnabledFor(logging.DEBUG):
            success_message = f'Created group "{group_name}". Permissions: {str(new_group.permissions)}'
            self.logger.debug(success_message)
        else:
            success_message = f'Created group "{group_name}". Permissions: {new_group.count_permissions()}'
            self.logger.info(success_message)

        return True, success_message
        

    @save_state_after
    def add_user_to_group(self, username:str, group_name:str) -> Tuple[bool, str]:
        self.logger.info(f'Adding user "{username}" to group "{group_name}"')

        if not self.user_exists(username):
            error_message = f'Tried to add non-existent user "{username}" to group {group_name}'
            self.logger.error(error_message)
            return False, error_message

        if not self.group_exists(group_name):
            error_message = f'Group "{group_name}" does not exist, could not add user "{username}"'
            self.logger.error(error_message)
            return False, error_message
        
        self.users[username].join_group(group_name)
        self.groups[group_name].add_member(username)

        success_message = f'Added user "{username}" to group "{group_name}"'
        self.logger.info(success_message)

        return True, success_message
    
    @save_state_after
    def add_permission_to_group(self, group_name:str, permission:Tuple[str, str]) -> Tuple[bool, str]:
        self.logger.info(f'Adding permission "{permission}" to group "{group_name}"')

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
        self.logger.info(f'Removing permission "{permission}" from group "{group_name}"')

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
    def remove_user_from_group(self, username:str, group_name:str) -> Tuple[bool, str]:
        if not self.user_exists(username):
            error_message = f'Tried to remove non-existent user "{username}"'
            self.logger.error(error_message)
            return False, error_message

        if not self.group_exists(group_name):
            error_message = f'Tried to remove user "{username}" from non-existent group {group_name}'
            self.logger.error(error_message)
            return False, error_message
        
        user = self.users[username]
        group = self.groups[group_name]

        if not user.in_group(group_name):
            error_message = f'User "{username}"is not member of group {group_name}'
            self.logger.warning(error_message)
            return False, error_message
        
        if user.in_group(group_name) != group.is_member(username):
            error_message = f'Mismatch in user "{username}" and group "{group_name}" member data! User groups: "{user.groups}". Group members: "{group.members}"'
            self.logger.critical(error_message)
            return False, error_message
        
        self.groups[group_name].remove_member(username)
        self.users[username].groups.remove(group_name)

        success_message = f'Removed user "{username}" from group "{group_name}"'
        self.logger.warning(success_message)
        return True, success_message
    
    @save_state_after
    def authorize_request(self, username:str, request:Tuple[str, str]) -> bool:
        data_type, data_id = request
        self.logger.info(f'User "{username}" requested access to "{request}"')

        if not self.user_exists(username):
            self.logger.error(f'Tried to authorize request for non-existent user "{username}"')
            return False
        
        if self.is_user_all_powerful(username):
            self.logger.info(f'Sword authorized "{username}" to "{data_id}"')
            return True
        
        user = self.users[username]

        if not user.setup_complete and not user.is_resetting_password:
            self.logger.warning(f'User "{username}" setup process is not complete. Could not authorize request')
            return False
        
        for group_name in user.groups:
            if not self.group_exists(group_name):
                self.logger.critical(f'User "{username}" is member of non-existent group "{group_name}"')  
                continue

            group = self.groups[group_name]

            if group.is_allowed_access(request):
                self.logger.info(f'Group "{group_name}" authorized "{username}" to "{data_id}"')
                return True
            
        self.logger.warning(f'User "{username}" tried to access "{data_id}"')
        return False
    
    @save_state_after
    def authenticate_user(self, username:str, password:str) -> Tuple[bool, str|None]:
        
        if not self.user_exists(username):
            self.logger.warning(f'User "{username}" not found, unable to authenticate')
            return False, None, False

        user = self.users[username]

        # check for uncompleted user but overwriten by password reset
        if not user.setup_complete and not user.is_resetting_password:
            self.logger.warning(f'User "{username}" setup process is not complete. Could not authenticate')
            return False, None, False
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()

        if not user.check_password(password_hash):
            self.logger.warning(f'Authentication faild for user "{username}" with password hash "{password_hash}"')
            return False, None, False
        
        session_auth_hash = user.new_session()
        self.logger.info(f'Authenticated user "{username}"')
        return True, session_auth_hash, self.is_user_all_powerful(username)

    def set_logging_level(self, logging_level) -> None:
        self.logger.setLevel(logging_level)

    def is_user_in_group(self, username:str, group_name:str) -> bool:
        if not self.group_exists(group_name):
            self.logger.error(f'Group "{group_name}" does not exist therefore is user "{username}" not member')
            return False
        
        if not self.user_exists(username):
            self.logger.error(f'User "{username}" does not exists therefore is not in group "{group_name}"')
            return False
        
        group = self.groups[group_name]

        return group.is_member(username)
    
    def save_state(self, file_path: str) -> None:
        """Saves the current state of users and groups to a file."""
        if self.use_azure_storage:
            try:

                blob_client = self.blob_service_client.get_blob_client(container=self.azure_container_name, blob=file_path)

                state_data = pickle.dumps((self.users, self.groups))
                blob_client.upload_blob(state_data, overwrite=True)

                # Save log file
                log_blob_client = self.blob_service_client.get_blob_client(container=self.azure_container_name, blob="log.txt")
                with open("log.txt", "rb") as log_file:
                    log_blob_client.upload_blob(log_file, overwrite=True)
                
                self.logger.debug(f'Successfully saved state and log to Azure Blob Storage: {file_path}')
            except Exception as e:
                self.logger.error(f'Failed to save state and log to Azure Blob Storage: {str(e)}')
        else:
            try:
                with open(file_path, 'wb') as file:
                    pickle.dump((self.users, self.groups), file)
                
                with open("log.txt", "rb") as log_file:
                    log_data = log_file.read()
                
                self.logger.debug(f'Successfully saved state and log to {file_path}')
            except Exception as e:
                self.logger.error(f'Failed to save state and log: {str(e)}')

    def load_state(self, file_path: str) -> None:
        """Loads the state of users and groups from a file."""
        if self.use_azure_storage:
            try:
                blob_client = self.blob_service_client.get_blob_client(container=self.azure_container_name, blob=file_path)
                
                if not blob_client.exists():
                    assert False, "Blob does not exist"

                state_data = blob_client.download_blob().readall()
                self.users, self.groups = pickle.loads(state_data)

                # Load log file
                log_blob_client = self.blob_service_client.get_blob_client(container=self.azure_container_name, blob="log.txt")
                with open("log.txt", "wb") as log_file:
                    log_file.write(log_blob_client.download_blob().readall())
                
                self.logger.info(f'Successfully loaded state and log from Azure Blob Storage: {file_path}')
                self.logger.info(f'All users: {list(self.users.keys())}')
                self.logger.info(f'Total number of users: {len(self.users.keys())}')
                self.logger.info(f'All groups: {list(self.groups.keys())}')
                self.logger.info(f'Total number of groups: {len(self.groups.keys())}')
            except Exception as e:
                self.logger.critical(f'Failed to load state and log from Azure Blob Storage: {str(e)}')
        else:
            try:
                if not os.path.exists(file_path):
                    assert False, "File does not exist"

                with open(file_path, 'rb') as file:
                    self.users, self.groups = pickle.load(file)
                
                self.logger.info(f'Successfully loaded state and log from {file_path}')
                self.logger.info(f'All users: {list(self.users.keys())}')
                self.logger.info(f'Total number of users: {len(self.users.keys())}')
                self.logger.info(f'All groups: {list(self.groups.keys())}')
                self.logger.info(f'Total number of groups: {len(self.groups.keys())}')
            except Exception as e:
                self.logger.critical(f'Failed to load state and log: {str(e)}')


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
    using_azure = os.environ['USE_AZURE_STORAGE']
    os.environ['USE_AZURE_STORAGE'] = "False" 
    manager = AccessManager(state_file_path="access_manager_test.state", load_state=False, name="AccessManagerTest")
    manager.set_logging_level(logging.DEBUG if debug else logging.CRITICAL)

    start_time = time.time()
    
    # Correct password hashes
    john_password = "password1"
    jack_password = "passwsord2"
    admin_password ="password3"
    
    output = '<div style="display:flex;flex-wrap:wrap;align-content:center;flex-direction: column;">'
    # Test creating users
    try:
        manager.create_user("john", john_password)
        manager.create_user("jack", jack_password)
        manager.create_user("admin", admin_password)
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
    output += format_results(manager.authenticate_user("john", john_password)[0], "Authentication passed for 'john' with correct password")
    output += format_results(manager.authenticate_user("jack", jack_password)[0], "Authentication passed for 'jack' with correct password")
    output += format_results(manager.authenticate_user("admin", admin_password)[0], "Authentication passed for 'admin' with correct password")

    # Test incorrect password
    output += format_results(not manager.authenticate_user("john", "wrongpasswordhash")[0], "Authentication failed for 'john' with incorrect password")
    output += format_results(not manager.authenticate_user("jack", "wrongpasswordhash")[0], "Authentication failed for 'jack' with incorrect password")
    output += format_results(not manager.authenticate_user("admin", "wrongpasswordhash")[0], "Authentication failed for 'admin' with incorrect password")

    # Test non-existent user
    output += format_results(not manager.authenticate_user("nonexistent", "passwordhash")[0], "Authentication failed for non-existent user")

    # Test empty username
    output += format_results(not manager.authenticate_user("", john_password)[0], "Authentication failed for empty username")

    # Test empty password
    output += format_results(not manager.authenticate_user("john", "")[0], "Authentication failed for empty password")

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
    success, message = manager.authenticate_user("emma", "passord4")
    if not success:
        output += format_results(True, f"Authentication failed for deleted user")
    else:
        output += format_results(False, f"Deleted user emma authenticated")
    

    output += format_results(True, "All tests completed!", use_emoji=False)

    end_time = time.time()
    output += f"Tests complete in {end_time - start_time:f}s"
    output += "</div>"

    manager.delete_logger()
    os.environ['USE_AZURE_STORAGE'] = using_azure 
    return output

# Performance tests for AccessManager
def performance_test_access_manager(debug):
    using_azure = os.environ['USE_AZURE_STORAGE']
    os.environ['USE_AZURE_STORAGE'] = "False" 
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

    manager.save_state("app/perf_test_save.state")
    # Performance test for rebooting
    start_time = time.time()
    for i in range(num_reboots):
        rebooted_manager = AccessManager(state_file_path="perf_test_save.state", name="AccessManagerPerformanceTest", init_log_level=performance_test_log_level)
        rebooted_manager.set_logging_level(performance_test_log_level)
        rebooted_manager.delete_logger()
        end_time = time.time()

    output += f"<h4>Time taken to reboot {num_reboots} times: {end_time - start_time:.4f} seconds</h4>"
    manager.delete_logger()

    os.environ['USE_AZURE_STORAGE'] = using_azure 
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


