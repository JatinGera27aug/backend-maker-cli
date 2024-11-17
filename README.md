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

## Code Snippets

Here are some of the core features of the generated structure:

### 1. MongoDB Connection (`config/dbMongo.js`)

```js
const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config()

function connectToDb() {
    try {
        mongoose.connect(process.env.MONGO_URI)
            .then(() => console.log('Connected to MongoDB'))
    } catch (err) {
        console.error(`Error: ${err.message}`);
        process.exit(1);
    }
}

module.exports = connectToDb;
```

Ensure you define the following in your `.env` file:
```
MONGO_URI=mongodb://your-mongo-uri
```

### 2. Multer File Upload Configuration (`config/multer.js`)

```js
const multer = require('multer');

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'public/uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname);
  }
});

const fileSizeLimit = 1024 * 1024 * 100; // 100MB file size limit

const upload = multer({
  storage: storage,
  limits: {
    fileSize: fileSizeLimit,
  },
  fileFilter: function (req, file, cb) {
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Only image files are allowed.'));
    }
    cb(null, true);
  }
});

module.exports = upload;
```

### 3. Authentication Model (`models/authModel.js`)

```js
const mongoose = require("mongoose");

const authSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, "Username is required"],
      unique: true,
      trim: true,
      minlength: [3, "Username must be at least 3 characters long"],
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      trim: true,
      match: [/S+@S+.S+/, "Please use a valid email address"],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [6, "Password must be at least 6 characters long"],
    },
  },
  { timestamps: true }
);

const authModel = mongoose.model("auth", authSchema);
module.exports = authModel;
```

### 4. JWT Authentication Middleware (`middleware/authMiddleware.js`)

```js
const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).send({ error: 'Access Denied' });
    
    try {
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send({ error: 'Invalid Token' });
    }
};

module.exports = authMiddleware;
```

### 5. Express Server Setup (`app.js`)

```js
const express = require('express');
const app = express();
const dotenv = require('dotenv');
dotenv.config();

app.use(express.json());
app.set(express.urlencoded({ extended: true }));
const cors = require('cors');
app.use(cors());

const connectDB = require('./config/db');
connectDB();

const authMiddleware = require('./middleware/authMiddleware');
const sampleRoutes = require('./routes/sampleRoutes.js');

const PORT = 8000 || process.env.PORT;

app.get('/', (req, res) => res.send('HELLO WORLD'));

app.use('/api', sampleRoutes);

app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});
```
---
