# Backend Maker CLI

This CLI tool is designed to streamline setting up a Node.js backend project. It includes features for setting up database configurations, adding necessary middleware, and initializing a project structure for ease of development 


# Backend Maker CLI

![npm](https://img.shields.io/npm/v/backend-maker-cli)
![npm](https://img.shields.io/npm/dt/backend-maker-cli)
![npm](https://img.shields.io/npm/dw/backend-maker-cli)
![GitHub Repo stars](https://img.shields.io/github/stars/JatinGera27aug/backend-maker-cli)
![GitHub issues](https://img.shields.io/github/issues/JatinGera27aug/backend-maker-cli)
![GitHub license](https://img.shields.io/github/license/JatinGera27aug/backend-maker-cli)


## Features

✅ **Quick Initialization**: Generate a project structure with MongoDB, MySQL, or no database.  
✅ **Modular Add-Ons**: Use simple commands to add Docker, Multer, Redis, Nodemailer, and more.  
✅ **Redis Support**: Pre-configured Redis caching for faster APIs.  
✅ **Developer-Friendly Defaults**: Comes with a clean folder structure, middleware, and basic routes.  
✅ **Extendable**: Easy-to-use commands to include advanced features as needed.  

---


## Commands

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

### 3. Redis Integration

This package now supports Redis for caching and improving API performance.  
Configuration is located in:  
- **Connection setup:** `./config/redis.js`  
- **Caching APIs:** `./utils/redis-cache.js` 

#### **Setup Redis**
Add the following variables to your `.env` file:
```bash
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password
```
Redis allows you to cache API responses, significantly boosting performance by reducing redundant database queries or computations.

#### Flexible Package Choice
You can choose between the **official `redis` package** and the **`ioredis` package** for Redis integration. When setting up Redis, an interactive CLI guides you through selecting your preferred package.

---

### 4. Docker Initialization (In Progress)

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
│   ├── dbMongo.js          # Database connection logic
│   ├── multer.js           # Multer configuration for file uploads
|   ├── redis.js            # Redis configuration for caching
|
|── constants/             # Constants for your application
│
├── controllers/             # Controllers for your routes
│   ├── authController.js    # Example controller
│
├── models/                  # Database models (e.g., User, Product)
│   ├── authModel.js         # Example model
│
├── middlewares/
|  ├── authMiddleware.js
|
├── routes/                  # Routes for your application
│   ├── sampleRoutes.js      # Example routes for user-related endpoints
│
├── public/                  # Public folder (for uploaded files)
│   └── uploads/             # Folder for storing file uploads
│
├── utils/                   # Utility functions and helpers
│   ├── emailSender.js       # Email sender utility
│   ├── redis-cache.js       # Redis caching utility
|
├── .env                     # Environment variables (Email, DB credentials, etc.)
├── .gitignore               # Git ignore file to prevent sensitive files from being tracked
├── app.js                   # Main server file to start your application
├── package.json             # NPM package configuration


```

## Code Snippets

Here are some of the core features of the generated structure:

### 1. Express Server Setup (`app.js`)

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


### 2. MongoDB Connection (`config/dbMongo.js`)

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

### 3. Multer File Upload Configuration (`config/multer.js`)

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

### 5. REDIS CACHE (`utils/redis-cache.js`)
```js
const redis = require('../config/redis');
const messages = require('../constants/redisMessages');

// Function to set a key in Redis with expiration
const setCache = async (key, value, ttl = 3600) => {
  try {
    await redis.set(key, JSON.stringify(value), 'EX', ttl);
    console.log("messages.CACHE_SET_SUCCESS" + key);
  } catch (err) {
    console.error(messages.SET_CACHE_ERROR + " " + key, err);
  }
};

// Function to get a key from Redis
const getCache = async (key) => {
  try {
    const data = await redis.get(key);
    return data ? JSON.parse(data) : null;
  } catch (err) {
    console.error(messages.GET_CACHE_ERROR + " " + key, err);

    return null;
  }
};

// Function to delete a key from Redis
const deleteCache = async (key) => {
  try {
    await redis.del(key);
    console.log("messages.CACHE_DELETED_SUCCESS" + key);
  } catch (err) {
    console.error(messages.DELETE_CACHE_ERROR + " " + key, err);

  }
};

module.exports = { setCache, getCache, deleteCache };

```

### 6. Email Sending (`utils/emailSender.js`)
```js
const nodemailer = require('nodemailer');
require('dotenv').config(); 

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL,  // Make sure to define EMAIL and PASS in your .env file
    pass: process.env.EMAIL_PASSWORD,  
  },
});

const sendEmail = (to, subject, text, html) => {
  const mailOptions = {
    from: process.env.EMAIL,  
    to: to, 
    subject: subject, 
    text: text, 
    html: html,  
  };

  return new Promise((resolve, reject) => {
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        return reject(error); 
      }
      resolve(info);
    });
  });
};

module.exports = sendEmail;
```

---

## **Contributing**  

Feel free to open issues or pull requests for improvements. Suggestions are always welcome!  

**License**: MIT  

--- 

