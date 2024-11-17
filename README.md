# Backend Maker CLI

This CLI tool is designed to streamline setting up a Node.js backend project. It includes features for setting up database configurations, adding necessary middleware, and initializing a project structure for ease of development 

## Features

- **`init`** command to initialize a backend project with MongoDB or MySQL database or none.
- **`add`** command to add optional features like Multer, Docker, MongoDB, MySQL, Nodemailer, etc boilerplate code

---

## Installation

To install the `backend-maker-cli` package globally, use npm:

```
npm install -g backend-maker-cli
```

Once installed, you can run the CLI commands from your terminal.

---

## Usage

### 1. Initialize Your Backend Project

To initialize your project structure, run:

```
backend-maker init
```

This will set up a basic backend project structure with default configurations.

If you want to set up a specific database (either MongoDB or MySQL) right at the start, you can use the following commands:

- For MongoDB:

```
backend-maker init --mongodb
```

- For MySQL:

```
backend-maker init --mysql
```

These commands will add the necessary database configurations to your project.

### 2. Adding Optional Features

After you initialize your project, you can add optional features as you require. Use the **`add`** command to add features like Multer, Docker, etc.

For example, to add Multer (for file uploading), run:

```
backend-maker add docker
```

This will generate a Dockerfile for your Node.js project

To learn more about available features, you can use the `--help` option:

```
backend-maker add --help
```

This will display a list of all the available features you can add to your project, including options for Docker, MongoDB, and more.

### 3. Docker Initialization (In Progress)

To initialize Docker configurations for your project, run:

```
docker init
```

---

## Folder Structure

Here is the folder structure for the generated project:

```
my-backend-project/
│
├── config/                 # Database, middleware, and general config files
│   ├── db.js               # Database connection logic
│   ├── multer.js           # Multer configuration for file uploads
│
├── controllers/             # Controllers for your routes
│   ├── authController.js    # Example controller
│
├── models/                  # Database models (e.g., User, Product)
│   ├── authModel.js         # Example model
│
|──middlewares/
|  |── authMiddleware.js
|
├── routes/                  # Routes for your application
│   ├── sampleRoutes.js      # Example routes for user-related endpoints
│
├── public/                  # Public folder (for uploaded files)
│   └── uploads/             # Folder for storing file uploads
│
├── .env                     # Environment variables (Email, DB credentials, etc.)
├── .gitignore               # Git ignore file to prevent sensitive files from being tracked
├── app.js                   # Main server file to start your application
├── package.json             # NPM package configuration

```

