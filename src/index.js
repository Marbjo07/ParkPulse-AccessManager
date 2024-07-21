const ACCESS_MANAGER_LOCATION = "https://parkpulse-accessmanager.azurewebsites.net"
//const ACCESS_MANAGER_LOCATION = "http://127.0.0.1:5050"

async function sha256(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

function fillOutTemplateForm(name, inputFields) {
    console.log(`creating template with ${JSON.stringify(inputFields)}`);

    inputFieldsHTMLCode = "";
    for (let i = 0; i < inputFields.length; i++) {
        field = inputFields[i];
        type = (field == "password") ? "password" : "text"
        inputFieldsHTMLCode += `
        <label for="${field.id}">${field.prompt}</label> 
        <input type="${type}" id="${field.id}"><br><br>`;
    }

    var formContent = `
        <h2>${name}</h2>
        ${inputFieldsHTMLCode}
        <button id="submit-button">Submit</button>`;
    return formContent;
}


function readFormFields() {
    var form = document.getElementById('popup-window');
    if (form) {
        var fields = form.elements;
        var values = {};
        for (var i = 0; i < fields.length; i++) {
            if (fields[i].type !== 'button') { // Ignore buttons
                values[fields[i].id] = fields[i].value;
            }
        }
        console.log(values);
        return values;
    }
}

function createPopup(name, inputFields, onSubmitFunction) {

    // Remove previous popup if any
    removePopup();
    if (name != "User Explorer") {
        closeVisualizer();
    }
    // Create the form element
    let form = document.createElement('form');
    form.id = "popup-window";
    form.addEventListener("submit", onSubmitFunction);

    let formContent = fillOutTemplateForm(name, inputFields);

    // Set the innerHTML of the form
    form.innerHTML = formContent;

    // Append the form to the container
    let container = document.getElementById('popup-container');
    container.appendChild(form);

    form.style.display = 'block';
}

function removePopup() {
    let container = document.getElementById('popup-container');
    container.innerHTML = "";
    
    let visualizer = document.getElementById('visualizer');
    visualizer.style.visibility = 'hidden';

}

async function defaultRequest(method, endpoint, body) {
    let data = {
        method: method,
        headers: {
            "Content-type": "application/json; charset=UTF-8"
        },
        body: JSON.stringify(body)
    };

    if (method == "GET") {
        delete data.body;
    }

    let response = await fetch(`${ACCESS_MANAGER_LOCATION}/${endpoint}`, data);

    let response_data = await response.json();

    if (response.ok) {
        createToast("success", response_data.message);
    }
    else {
        createToast("error", response_data.error);
    }

    return response_data;
}



function endpointHandler(endpoint) {
    let fields = readFormFields();
    removePopup();
    defaultRequest("POST", endpoint, fields);
}

function endpointHandlerWithConfirmation(endpoint, confirmationPrompt, confirmationDataField) {
    let fields = readFormFields();
    let answer = null;
    if (confirmationDataField == "y/n") {
        answer = prompt(confirmationPrompt + confirmationDataField);
    }
    else {
        answer = prompt(confirmationPrompt + fields[confirmationDataField]);
    }

    removePopup();
    if ((confirmationDataField == "y/n" && answer == "y") ||
        (answer == fields[confirmationDataField])
    ) {
        defaultRequest("POST", endpoint, fields);
    }
}

function visualizeUsers(data) {
    const visualizer = document.getElementById('visualizer');
    visualizer.style.visibility = 'visible';

    const userContainer = document.getElementById('container');
    data.users.forEach(userStr => {
        const user = JSON.parse(userStr);

        const userDiv = document.createElement('div');
        userDiv.className = 'user';

        const userNameDiv = document.createElement('div');
        userNameDiv.className = 'user-name';
        userNameDiv.textContent = `User Name: ${user.username}`; 

        const groupsDiv = document.createElement('div');
        groupsDiv.className = 'groups';
        groupsDiv.textContent = 'Groups: ';
        user.groups.forEach(group => {
            const groupDiv = document.createElement('span');
            groupDiv.className = 'group';

            groupDiv.textContent = group;
            groupsDiv.appendChild(groupDiv);
        });

        userDiv.appendChild(userNameDiv);
        userDiv.appendChild(groupsDiv);
        userContainer.appendChild(userDiv);
    });
}

function visualizeUser(data) {
    data = JSON.parse(data);
    const visualizerContainer = document.getElementById('visualizer');
    visualizerContainer.style.visibility = "visible"

    // Create the container div
    const containerDiv = document.getElementById('container');
    
    // Create and append the user name
    const userName = document.createElement('h2');
    userName.className = "name-header"
    userName.textContent = `User Name: ${data.username}`;
    containerDiv.appendChild(userName);

    const onlineStatus = document.createElement('p');
    onlineStatus.textContent = (data.online) ? "online" : "offline";
    containerDiv.appendChild(onlineStatus);  

    
    const setupStatus = document.createElement('p');
    setupStatus.textContent = "setup " + ((data.setup_complete) ? "complete" : "inprogress");
    containerDiv.appendChild(setupStatus);  

    const groupContainer = document.createElement('div');
    groupContainer.className = 'group-container';
    console.log(data.groups);
    
    data.groups.forEach(groupStr => {
        const group = JSON.parse(groupStr);

        // Create group div
        const groupDiv = document.createElement('div');
        groupDiv.className = 'group';

        // Add group name
        const groupName = document.createElement('p');
        groupName.innerHTML = `<strong>Group Name:</strong></br>${group.group_name}`;
        groupName.className = 'group-name';
        groupDiv.appendChild(groupName);

        // Add permissions
        const permissions = document.createElement('p');
        const permissionsContent = Object.entries(group.permissions).map(([key, value]) => {
            return `<strong>${key}:</strong> ${value.join(', ') || 'None'}`;
        }).join('<br>');
        permissions.innerHTML = `<strong>Permissions:</strong><br>${permissionsContent || 'None'}`;
        groupDiv.appendChild(permissions);

        groupContainer.appendChild(groupDiv);
    });
    containerDiv.appendChild(groupContainer);

}

function visualizeGroup(data) {
    data = JSON.parse(data);
    const visualizerContainer = document.getElementById('visualizer');
    visualizerContainer.style.visibility = "visible"

    // Create the container div
    const containerDiv = document.getElementById('container');
    
    // Create and append the user name
    const groupName = document.createElement('h2');
    groupName.className = "name-header"
    groupName.textContent = `Group Name: ${data.group_name}`;
    containerDiv.appendChild(groupName);

    const groupContainer = document.createElement('div');
    groupContainer.className = 'group-container';

    // Add permissions
    const permissions = document.createElement('p');
    console.log(data.permissions)
    const permissionsContent = Object.entries(data.permissions).map(([key, value]) => {
        return `<strong>${key}:</strong> ${value.join(', ') || 'None'}`;
    }).join('<br>');
    permissions.innerHTML = `<strong>Permissions:</strong><br>${permissionsContent || 'None'}`;
    groupContainer.appendChild(permissions);

    // Add permissions
    const members = document.createElement('p');
    members.innerHTML = `<strong>Members:</strong> ${data.members.join(', ') || 'None'}`;
    groupContainer.appendChild(members);

    containerDiv.appendChild(groupContainer);
}


function closeVisualizer() {
    const visualizer = document.getElementById('visualizer');
    visualizer.style.visibility = 'hidden';

    const userContainer = document.getElementById('container');
    userContainer.innerHTML = "";
}

async function userExplorerPopup() {
    createPopup(
        "User Explorer",
        [
            { id: "username", prompt: "Username" },
        ],
        () => {
            let fields = readFormFields();
            removePopup();
            defaultRequest("POST", "/list_user", { "username": fields.username })
                .then((response) => {
                    console.log(response.user);
                    visualizeUser(response.user)
                });
        }
    );

}
async function groupExplorerPopup() {
    createPopup(
        "Group Explorer",
        [
            { id: "group_name", prompt: "Group" },
        ],
        () => {
            let fields = readFormFields();
            removePopup();
            defaultRequest("POST", "/list_group", { "group_name": fields.group_name })
                .then((response) => {
                    console.log(response.group);
                    visualizeGroup(response.group)
                });
        }
    );

}

function createUserPopup() {
    createPopup(
        "Create User",
        [
            { id: "username", prompt: "Username" },
            { id: "password", prompt: "Password" },
            { id: "password_hash", prompt: "Password Hash" },
        ],
        async () => {
            let fields = readFormFields();
            removePopup();
            
            if (fields.password != "" && fields.password_hash != "") {
                alert("Bro only one at a time");
                return;
            }

            if (fields.password != "") {
                fields.password_hash = await sha256(fields.password)
            }

            if (fields.password == "" && fields.password == "") {
                alert('Must fill one of the fields, cant setup onboarding link her, mate')
                return;
            }

            defaultRequest("POST", "/create_user", fields);
        }
    );
}

function setupOnboardingPopup() {
    createPopup(
        "Setup Onboarding Link",
        [
            {id: "username", prompt: "Username"}
        ],
        () => {
            endpointHandler("/setup_onboarding");
        }
    )
}

function deleteUserPopup() {
    createPopup(
        "Delete User",
        [
            { id: "username", prompt: "User" },
        ],
        () => {
            endpointHandlerWithConfirmation("/delete_user", "Are you sure you want to delete ", "username");
        }
    );
}


function disableUserSessionPopup() {
    createPopup(
        "Disable User Session",
        [
            { id: "username", prompt: "User" },
        ],
        () => {
            endpointHandlerWithConfirmation("/disable_user_session", "Are you sure you want to disable ", "y/n");
        }
    );
}


function createGroupPopup() {
    createPopup(
        "Create Group",
        [
            { id: "group_name", prompt: "Group" },
        ],
        () => {
            endpointHandler("/create_group")
        }
    );
}


function deleteGroupPopup() {
    createPopup(
        "Delete Group",
        [
            { id: "group_name", prompt: "Group" },
        ],
        () => {
            endpointHandlerWithConfirmation("/delete_group", "Are you sure you want to delete ", "group_name");
        }
    );
}


function addUserToGroupPopup() {
    createPopup(
        "Add User to Group",
        [
            { id: "username", prompt: "User" },
            { id: "group_name", prompt: "Group" },
        ],
        () => {
            endpointHandler("/add_user_to_group");
        }
    );
}


function addPermissionToGroupPopup() {
    createPopup(
        "Add Permission to Group",
        [
            { id: "group_name", prompt: "Group" },
            { id: "data_type", prompt: "Data Type" },
            { id: "data_ids", prompt: "Data Ids" },
        ],
        () => {
            endpointHandler("/add_permissions_to_group");
        }
    );
}


function removeUserFromGroupPopup() {
    createPopup(
        "Remove User from Group",
        [
            { id: "username", prompt: "User" },
            { id: "group_name", prompt: "Group" },
        ],
        () => {
            endpointHandler("/remove_user_from_group");
        }
    );
}


function removePermissionFromGroupPopup() {
    createPopup(
        "Remove Permission from Group",
        [
            { id: "group_name", prompt: "Group" },
            { id: "data_type", prompt: "Data Type" },
            { id: "data_ids", prompt: "Data Ids" },
        ],
        () => {
            endpointHandler("/remove_permissions_from_group");
        }
    );
}


function deleteGroupPopup() {
    createPopup(
        "Delete Group",
        [
            { id: "group_name", prompt: "Group" },
        ],
        () => {
            endpointHandlerWithConfirmation("/delete_group", "Are you sure you want to delete ", "group_name");
        }
    );
}

