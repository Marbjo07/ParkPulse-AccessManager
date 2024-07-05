function fillOutTemplateForm(name, inputFields) {
    console.log(`creating template with ${JSON.stringify(inputFields)}`);

    inputFieldsHTMLCode = "";
    for (let i = 0; i < inputFields.length; i++) {
        field = inputFields[i];
        inputFieldsHTMLCode += `
        <label for="${field.id}">${field.prompt}</label> 
        <input type="text" id="${field.id}"><br><br>`;
    }

    var formContent = `
        <h2>${name}</h2>
        ${inputFieldsHTMLCode}
        <button id="submit-button">Create</button>`;
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
    // Create the form element
    var form = document.createElement('form');
    form.id = "popup-window";
    form.addEventListener("submit", onSubmitFunction);

    var formContent = fillOutTemplateForm(name, inputFields);

    // Set the innerHTML of the form
    form.innerHTML = formContent;

    // Append the form to the container
    var container = document.getElementById('popup-container');
    container.appendChild(form);

    form.style.display = 'block';
}

function removePopup() {
    var container = document.getElementById('popup-container');
    container.innerHTML = "";
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

    return await fetch(`http://127.0.0.1:5050/${endpoint}`, data)
    .then((response) => {
        return response.json();
    })
    .then((data) => {
        if (data.message != null) {
            createToast("success", data.message);
        }
        return data;
    })
    .catch((error) => {
        console.log(error);
    })
}



function endpointHandler(endpoint) {
    let fields = readFormFields();
    removePopup();
    defaultRequest("POST", endpoint, fields);
}   

function endpointHandlerWithConfirmation(endpoint, confirmationPrompt, confirmationDataField) {
    let fields = readFormFields();
    let answer = prompt(confirmationPrompt + fields[confirmationDataField]);

    removePopup();
    if (answer == fields[confirmationDataField]) {
        defaultRequest("POST", endpoint, fields);
    }
}

function userExplorerPopup() {
    defaultRequest("GET", "/list_users", {})
}

function createUserPopup() {
    createPopup(
        "Create User", 
        [
            {id: "user_name", prompt: "Username"},
            {id: "password_hash", prompt: "Password"},
        ], 
        () => {
            endpointHandler("/create_user")
        }
    );
}

function deleteUserPopup() {
    createPopup(
        "Delete User", 
        [
            {id: "user_name", prompt: "User"},
        ], 
        () => {
            endpointHandlerWithConfirmation("/delete_user", "Are you sure you want to delete ", "user_name");
        }
    );
}


function createGroupPopup() {
    createPopup(
        "Create Group", 
        [
            {id: "group_name", prompt: "Group"},
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
            {id: "group_name", prompt: "Group"},
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
            {id: "user_name", prompt: "User"},
            {id: "group_name", prompt: "Group"},
        ], 
        () => {
            endpointHandler("/add_user_to_group");
        }
    );
}

