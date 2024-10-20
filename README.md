<div align="center">
  <h1 align="center">Access Manager</h1>
  <h3>A simple user manager.</h3>
</div>

<br/>

ParkPulse AccessManager is a open-source user authentication and authorization service.

## Features

- **User Setup:** Create a user onboarding link with a few clicks.
- **Group Users:** Create groups, add users and give permissions.
- **Password Reset:** Request a password reset, and, kabow the user receives an email with simple instructions and a link.
- **Easy integration:** Implement a few endpoints and have a fully working authentication system. 

## Tech Stack

- [![Python][Python-logo]][Python-url]
- [![Flask][Flask-logo]][Flask-url]
- [![JavaScript][JS-logo]][JS-url]
- [![Docker][Docker-logo]][Docker-url]
- Azure Blob Storage
- Azure Entra ID

## Getting Started

### Prerequisites

Here's what you need to run Access Manager locally:

- Docker

### 1. Clone the repository

```shell
git clone https://github.com/Marbjo07/ParkPulse-AccessManager.git
cd ParkPulse-AccessManager
```

### 2. Define `.env` file

``` shell
USE_AZURE_STORAGE="False"
FLASK_ENV=development
ACCESS_MANAGER_URL="http://localhost:5000"
BACKEND_SERVER_URL=""
FRONTEND_URL=""
```

### 3. Run the dev server

```shell
docker build -f Dockerfile.dev -t accessmanager .
docker run  --env-file=.env -p 5000:5000 -t accessmanager
```

### 4. Open the app in your browser

Visit [http://localhost:5000/login](http://localhost:5000/login) in your browser.

### 5. Login

- **Username:** admin
- **Password:** admin

### 6. Create an example user

Hover over **Function Menu**, click **Create User** and fillout `Username` and either `Password` or `Password Hash`

### 7. Test user login

Use console in dev tools (Ctrl + Shift + i)

``` js
let data = {username: ..., passwordHash: ... (sha256 of password)};

fetch("/authenticate_user", {
  method: "POST", 
  headers: {"Content-type": "application/json;"},
  body: JSON.stringify(data)
}).then(res => {
  console.log("Request complete! response:", res);
});
```

## Usage

**Note**: username must be the email of the user

1. On user login simply pass passwordHash and username to `/authenticate_user` and read **"authenticate"** from the json response. Save **"auth_hash"** for authentication when `/disable_user_session` is called.

2. Implement `/disable_user_session` on your server. It should accept **POST** requests with the args **"username"** and **"auth_str"**. Check that the sha256 of **"auth_str"** match the **"auth_hash"** returned after the user logged in.

3. Define `SLACK_WEBHOOK_URL`, `AZURE_BLOB_SERVICE_URL`, `AZURE_CONTAINER_NAME`, `CONNECTION_STRING` (Azure Communication Services email), `EMAIL_SENDER_ADDRESS` and set `USE_AZURE_STORAGE = "True"` and `ADMIN_PASSWORD_HASH` (double sha256) to something secret in the env file.

4. Implement a user interface for `/finish_onboarding` and `/request_password_reset`

5. (Optional) use `/authorize_request` or **"allowedDataSources"** returned from `/authenticate_user` to check if user has access to a resource.

## API Documentation

### /finish_onboarding

- Completes user setup and makes user account valid or sets a new password for user
- **Method:** `POST`
- **Args:**
  - `username` (str): Username of the new user
  - `passwordHash` (str): Hash of user password
  - `token` (str): Token verifying the link caller
- **Returns:** A JSON object with either
  - `message` (str|None): Success message  
  - `error` (str|None): Error message  
- **Status Codes:** `201`, `400`

### /request_password_reset

- Sends an email to the user specified with a password reset link
- **Method:** `POST`
- **Args:** 
  - `username` (str): The user requesting a password reset link
- **Returns:** A JSON object with either
  - `message` (str|None): Success message  
  - `error` (str|None): Error message  
- **Status Codes:** `200`, `400`

### /list_available_cities

- Lists the cities a user has access to
- **Method:** `POST`
- **Args:** username
- **Returns:** json object with "message" or "error" depending on success
- **Status Codes:** `200`, `400`

### /authorize_request

- Checks if user has access to resource
- **Method:** `POST`
- **Args:** 
  - `username` (str): The username of the user
  - `request`: (<a href="#data-types">Data Source</a>): Requested data source1
- **Returns:** A JSON object
  - `authorized` (boolean): If authorization was successful
- **Status Codes:** `200`, `401`

### /authenticate_user

- Authenticates a user and returns access information.
- **Method:** `POST`
- **Args:**  
  - `username` (str): The username of the user attempting to authenticate.  
  - `passwordHash` (str): Hash of user password
- **Returns:** A JSON object with the following keys:  
  - `authenticated` (boolean): If authentication was successful.  
  - `auth_hash` (str): A hash used to authenticate the access manager when calling the `/disable_user_session` endpoint on the client server.  
  - `isDev` (boolean): Specifies if the user is a developer
  - `allowedDataSource` (list): A list of data sources the user is allowed to access. On auth fail this is empty
- **Status Codes:** `200`, `401`

<a id="data-types"></a>

### Data types

- Data Source / Resource:

  - **data_type:** the type of data or resource type (e.g "images", "map_locations", "connection_logs", etc)
  - **data_id:** the id of the data (e.g "image_238.png", "new york", "session_6395.log", etc)

## Contributing

Access Manager is an open-source project, and we welcome contributions from the community.

If you'd like to contribute, please fork the repository and make any changes you'd like. Pull requests are warmly welcome.

### Our Contributors ✨

<a href="https://github.com/Marbjo07/ParkPulse-AccessManager/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=Marbjo07/ParkPulse-AccessManager"/>
</a>


<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[Python-logo]: https://img.shields.io/badge/Python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54
[Python-url]: https://www.python.org/
[Flask-logo]: https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white
[Flask-url]: https://flask.palletsprojects.com/
[JS-logo]: https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black
[JS-url]: https://developer.mozilla.org/en-US/docs/Web/JavaScript
[Docker-logo]: https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white
[Docker-url]: https://www.docker.com/