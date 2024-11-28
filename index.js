#!/usr/bin/env node

import { Command } from 'commander';
import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import inquirer from 'inquirer';

const program = new Command();
const projectPath = process.cwd();


const createPackageJson = (projectPath) => {
  const packageJsonPath = path.join(projectPath, 'package.json');
  if (!fs.existsSync(packageJsonPath)) {
    console.log('Creating package.json...');
    execSync('npm init -y', { stdio: 'inherit' });
  } else {
    console.log('package.json already exists, skipping...');
  }
};

// const installDependencies = () => {
//     console.log('Installing dependencies...');
//     const dependencies = ['express', 'mongoose', 'jsonwebtoken', 'dotenv', 'cors', 'multer', 'mysql2', 'bcryptjs', 'express-validator', 'nodemailer', 'api-rate-limiter-middleware'];
//     execSync(`npm install ${dependencies.join(' ')}`, { stdio: 'inherit' });
//     console.log('Dependencies installed successfully!');
//   };

const installDependencies = (dbChoice) => {
    console.log('Installing dependencies...');
    const commonDependencies = ['express', 'jsonwebtoken', 'dotenv', 'cors', 'multer', 'bcrypt', 'express-validator'];
    if (!dbChoice) execSync(`npm install ${commonDependencies.join(' ')}`, { stdio: 'inherit' });
    else{
        const dbDependencies =
      dbChoice === 'mongodb' ? ['mongoose'] : ['mysql2', 'sequelize'];
    execSync(`npm install ${[...commonDependencies, ...dbDependencies].join(' ')}`, { stdio: 'inherit' });
    }
    console.log('Dependencies installed successfully!');
  };

// Function to create backend structure
const createBackendStructure = () => {
    const folders = ['models', 'controllers', 'routes', 'middleware', 'utils', 'config', 'public', 'constants', 'api-rate-limiter-middleware'];
  
    // to create common files
    folders.forEach((folder) => {
      const folderPath = path.join(projectPath, folder);
      if (!fs.existsSync(folderPath)) {
        fs.mkdirSync(folderPath, { recursive: true });
        console.log(`Created folder: ${folder}`);
      }
    });
  
    // Generate common files
    generateAppFile();
  };


const generateAppFile = () => {
    
  // Create app.js
  const appContent = 
`const express = require('express');
const app = express();
const dotenv = require('dotenv');
dotenv.config()

app.use(express.json());
app.set(express.urlencoded({ extended: true }));
const cors = require('cors');
app.use(cors());
const connectDB = require('./config/dbMongo.js');
connectDB();
const sampleRoutes = require('./routes/sampleRoutes.js')

const PORT = 8000 || process.env.PORT;

app.get('/', (req, res) => res.send('HELLO WORLD'));

app.use('/api',sampleRoutes)

app.listen(PORT, () => {
    console.log("Server is running at http://localhost:8000");
});`;
  fs.writeFileSync(path.join(projectPath, 'app.js'), appContent);
  console.log('Generated app.js');

  // Create middleware/authMiddleware.js
const authMiddlewareContent = 
`const jwt = require('jsonwebtoken');
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
module.exports = authMiddleware;`;
  const middlewareFolderPath = path.join(projectPath, 'middleware');
  fs.writeFileSync(path.join(middlewareFolderPath, 'authMiddleware.js'), authMiddlewareContent);
  console.log('Generated middleware/authMiddleware.js');


// model/authModel.js
const authModelContent = 
`const mongoose = require("mongoose");

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
      trim: true
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [4, "Password must be at least 4 characters long"],
    },
  },
  { timestamps: true }
);

const authModel = mongoose.model("auth", authSchema);
module.exports = authModel;

`
const ModelFolderPath = path.join(projectPath, 'models');
  fs.writeFileSync(path.join(ModelFolderPath, 'authModel.js'), authModelContent);
  console.log('Generated middleware/authModel.js');



// controllers/authController.js
const authControllerContent =
`const authModel = require("../models/authModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

class AuthController {
  // **User Registration**
  static userRegistration = async (req, res) => {
    console.log("Registration request received:", req.body);
    const { username, email, password } = req.body;

    try {
      // Validate input
      if (!username || !email || !password) {
        return res.status(400).json({ message: "All fields are required" });
      }

      // Check if user exists
      const existingUser = await authModel.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: "User already exists. Please log in." });
      }

      // Hash password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Save new user
      const newUser = new authModel({ username, email, password: hashedPassword });
      const savedUser = await newUser.save();

      return res.status(201).json({
        message: "User registered successfully",
        user: { id: savedUser._id, username: savedUser.username, email: savedUser.email },
      });
    } catch (error) {
      console.error("Error during registration:", error);
      return res.status(500).json({ message: "Internal server error" });
    }
  };

  // **User Login**
  static userLogin = async (req, res) => {
    console.log("Login request received:", req.body);
    const { email, password } = req.body;

    try {
      // Validate input
      if (!email || !password) {
        return res.status(400).json({ message: "All fields are required" });
      }

      // Find user
      const user = await authModel.findOne({ email });
      if (!user) {
        return res.status(404).json({ message: "User does not exist. Please register." });
      }

      // Validate password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: "Invalid credentials. Please try again." });
      }

      // Generate token
      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1d" });

      return res
        .status(200)
        .header("auth-token", token)
        .json({ message: "Login successful", token, username: user.username });
    } catch (error) {
      console.error("Error during login:", error);
      return res.status(500).json({ message: "Internal server error" });
    }
  };
}

module.exports = AuthController;

`
const ControllerFolderPath = path.join(projectPath, 'controllers');
  fs.writeFileSync(path.join(ControllerFolderPath, 'authController.js'), authControllerContent);
  console.log('Generated middleware/authController.js');


// middleware/validationAuthMiddleware.js
const validationAuthMiddlewareContent =
`const validateAuthInput = (req, res, next) => {
  const { username, email, password } = req.body;

  if (req.path.includes("register") && (!username || username.trim().length < 3)) {
    return res.status(400).json({ message: "Username must be at least 3 characters long" });
  }

  if (!email) {
    return res.status(400).json({ message: "Email is required" });
  }

  if (!password || password.trim().length < 4) {
    return res.status(400).json({ message: "Password must be at least 4 characters long" });
  }

  next();
};

module.exports = validateAuthInput;

`
  fs.writeFileSync(path.join(middlewareFolderPath, 'validationAuthMiddleware.js'), validationAuthMiddlewareContent);
  console.log('Generated middleware/validationAuthMiddleware.js');


// routes/sampleRoutes.js
const sampleRoutesContent =
`const express = require("express");
const AuthController = require("../controllers/authController");
const validateAuthInput = require("../middleware/validationAuthMiddleware");
const authMiddleware = require("../middleware/authMiddleware");

const router = express.Router();

// User Registration
router.post("/register", validateAuthInput, AuthController.userRegistration);

// User Login
router.post("/login", validateAuthInput, AuthController.userLogin);

// Protected Route Example
// router.get('/get/allUsers', authMiddleware, AuthController.getAllUsers);

// -- replace getAllUsers with your actual controller function --
module.exports = router;

`
const RoutesFolderPath = path.join(projectPath, 'routes');
  fs.writeFileSync(path.join(RoutesFolderPath, 'sampleRoutes.js'), sampleRoutesContent);
  console.log('Generated middleware/sampleRoutes.js');



// .env
 const envContent = 
`PORT = 8000
JWT_SECRET = "your-secret-key"
MONGO_URI=mongodb+srv://<username>:<password>@cluster.mongodb.net/mydb

`;
   fs.writeFileSync(path.join(projectPath, '.env'), envContent);
   console.log('Generated .env file');
 

// .gitignore
const gitignoreContent =
`node_modules/
.env
`;
   fs.writeFileSync(path.join(projectPath, '.gitignore'), gitignoreContent);
   console.log('Generated .gitignore file');
};


// Create config/db.js
const generateMongoDBConfig = () => {
    const dbMongoContent = 
`const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config()
  
function connectToDb() {
    try{
        mongoose.connect(process.env.MONGO_URI)
        .then(() => console.log('connected to db'))
    } catch(err){
        console.error(\`Error: \${err.message}\`);
        process.exit(1);
    }
}
// connectToDb();
module.exports = connectToDb;
  `;
    const configFolderPath = path.join(projectPath, 'config');
    fs.appendFileSync(path.join(configFolderPath, 'dbMongo.js'), dbMongoContent);
    console.log('Generated config/dbMongo.js');
  };
  
  
  // generate Mysql config
const generateMySQLConfig = () => {
    const dbMysqlContent = 
`const { Sequelize } = require("sequelize");

// Configure Sequelize instance with options
const sequelize = new Sequelize(process.env.MYSQL_URI, {
    dialect: "mysql",
    logging: process.env.SEQUELIZE_LOGGING === "true" ? console.log : false, // Toggle query logging
    pool: {
        max: 5, // Maximum number of connections in pool
        min: 0, // Minimum number of connections in pool
        acquire: 30000, // Maximum time (ms) to get a connection
        idle: 10000, // Maximum time (ms) a connection can be idle
    },
    retry: {
        max: 3, // Retry connection attempts
    },
});

// Async function to connect to the database
const connectDB = async () => {
    try {
        await sequelize.authenticate();
        console.log("✅ MySQL Connected successfully.");
    } catch (err) {
        console.error("❌ Unable to connect to the database. Please check the connection details:", err.message);

        // Retry mechanism for better fault tolerance
        console.error("⚠️ Retrying database connection...");
        setTimeout(async () => {
            try {
                await sequelize.authenticate();
                console.log("✅ MySQL Reconnected successfully after retry.");
            } catch (retryErr) {
                console.error("❌ Retry failed. Exiting application:", retryErr.message);
                process.exit(1); // Exit the application in case of persistent failure
            }
        }, 5000);
    }
};

// Export both the Sequelize instance and the connection function
module.exports = { sequelize, connectDB };
`;
      const configFolderPath = path.join(projectPath, 'config');
      fs.writeFileSync(path.join(configFolderPath, 'dbMysql.js'), dbMysqlContent);
      console.log('Generated config/dbMysql.js');

const envContent = 
`MYSQL_URI=mysql://<username>:<password>@localhost:3306/mydb
SEQUELIZE_LOGGING=true

`;
      fs.appendFileSync(path.join(projectPath, '.env'), envContent);
      console.log('Generated .env file');
      
  };  


// config/multer.js
const generateMulterConfig = () =>{
    const multerContent = `
const multer = require('multer');

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // You can change 'public/uploads/' to any directory you want
    cb(null, 'public/uploads/');
  },
  // Define how the file will be named on the server
  filename: function (req, file, cb) {
    // You must use the 'file' object that multer automatically passes to this function
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
    // You can specify file type filters here if needed
    // For example, accept only images
    if (!file.mimetype.startsWith('image/')) {
      return cb(new Error('Only image files are allowed.'));
    }
    cb(null, true); // Accept the file if it passes the filter
  }
});

module.exports = upload;
`

const configFolderPath = path.join(projectPath, 'config');
    fs.writeFileSync(path.join(configFolderPath, 'multer.js'), multerContent);
    console.log('Generated config/multer.js');
};


// middlewares/rateLimiter.js
const generateRateLimiterMiddleware = () => {
    const rateLimiterContent = 
`const createRateLimiter = require('api-rate-limiter-middleware');

// Apply the rate limiter with a 5-minute window and a maximum of 10 requests per IP
const limiter = createRateLimiter({ minutes: 5, maxRequests: 10 });
module.exports = limiter;

`
const middlewareFolderPath = path.join(projectPath, 'middleware');
  fs.writeFileSync(path.join(middlewareFolderPath, 'rateLimiter.js'), rateLimiterContent);
  console.log('Generated middleware/rateLimiter.js');
};


// utils/emailSender.js
const generateEmailSender = () => {

  execSync('npm install nodemailer', { stdio: 'inherit' });
  console.log("nodemailer installed successfully...")

    const emailSenderContent = 
`const nodemailer = require('nodemailer');
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

// e.g. sendEmail('recipient@example.com', 'demo Subject', 'Namaste from sender'
// , '<p>Namaste from sender<b>HTML</b></p>')

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
`
const utilsFolderPath = path.join(projectPath, 'utils');
  fs.writeFileSync(path.join(utilsFolderPath, 'emailSender.js'), emailSenderContent);
  console.log('Generated utils/emailSender.js');

};


// config/s3.js
const generateS3Config = () => {

  execSync('npm install aws-sdk', { stdio: 'inherit' });
  console.log("aws-sdk installed successfully.");


    const s3ConfigContent = 
`const AWS = require('aws-sdk');
require('dotenv').config();

const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION,
});

module.exports = s3;
`

const configFolderPath = path.join(projectPath, 'config');
      fs.writeFileSync(path.join(configFolderPath, 's3.js'), s3ConfigContent);
      console.log('Generated config/s3.js');

// .env for aws-s3
const envContent = 
`AWS_ACCESS_KEY_ID=your-access-key-id
AWS_SECRET_ACCESS_KEY=your-secret-access-key
AWS_REGION=your-bucket-region

`;
  fs.appendFileSync(path.join(projectPath, '.env'), envContent);
  console.log('Generated .env file');
  
}



// cloudinary implementation
const generateCloudinaryConfig = () => {
  execSync('npm install cloudinary', { stdio: 'inherit' });
  console.log("cloudinary installed successfully.");

  const cloudinaryContent =
`const cloudinary = require("cloudinary").v2;
const path = require("path");

// Configure Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

// Utility function to validate Cloudinary configuration
const validateCloudinaryConfig = () => {
    if (!process.env.CLOUDINARY_CLOUD_NAME || 
        !process.env.CLOUDINARY_API_KEY || 
        !process.env.CLOUDINARY_API_SECRET) {
        throw new Error(
            "Cloudinary configuration is missing. Please set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET in your .env file."
        );
    }
};

// Function to upload a file to Cloudinary
const uploadToCloudinary = async (filePath, options = {}) => {
    try {
        validateCloudinaryConfig();

        // Default options with overrides
        const defaultOptions = {
            folder: "default",
            use_filename: true, // Preserve the file's original name
            unique_filename: false, // Avoid auto-generating unique filenames
        };

        const uploadOptions = { ...defaultOptions, ...options };

        // Validate filePath
        if (!filePath || typeof filePath !== "string") {
            throw new Error("Invalid file path provided for upload.");
        }

        // Ensure the file exists
        const resolvedPath = path.resolve(filePath);

        // Perform upload
        const result = await cloudinary.uploader.upload(resolvedPath, uploadOptions);

        console.log("✅ File uploaded to Cloudinary:", result.secure_url);

        return {
            url: result.secure_url,
            publicId: result.public_id, // For future management like deletions
            folder: result.folder, // Useful for organization
        };
    } catch (error) {
        console.error("❌ Cloudinary upload error:", error.message);
        throw error;
    }
};

// Function to delete a file from Cloudinary by public ID
const deleteFromCloudinary = async (publicId) => {
    try {
        validateCloudinaryConfig();

        if (!publicId) {
            throw new Error("Public ID is required for deletion.");
        }

        const result = await cloudinary.uploader.destroy(publicId);

        if (result.result === "ok") {
            console.log("✅ File deleted from Cloudinary:", publicId);
        } else {
            console.error("❌ Error deleting file from Cloudinary:", result);
        }

        return result;
    } catch (error) {
        console.error("❌ Cloudinary deletion error:", error.message);
        throw error;
    }
};

module.exports = { uploadToCloudinary, deleteFromCloudinary };


`

const configFolderPath = path.join(projectPath, 'config');
    fs.writeFileSync(path.join(configFolderPath, 'cloudinary.js'), cloudinaryContent);
    console.log('Generated config/multer.js');

// env for cloudinary
const envContent = 
`CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-cloudinary-api
CLOUDINARY_API_SECRET=your-cloudinary-api-secret

`;
  fs.appendFileSync(path.join(projectPath, '.env'), envContent);
  console.log('Generated .env file');

}

// ioredis implementation 
const implementRedis = () => {

  execSync('npm install ioredis ', { stdio: 'inherit' });
  console.log("ioredis installed successfully.");

  const redisConfigContent = 
`const Redis = require('ioredis');
require('dotenv').config();

// Create a Redis client
const redis = new Redis({
  host: process.env.REDIS_HOST || '127.0.0.1',
  port: process.env.REDIS_PORT || 6379,
  password: process.env.REDIS_PASSWORD || '', // Optional: Provide password for secured Redis
});


redis.on('connect', () => {
  console.log('Connected to Redis!');
});

redis.on('error', (err) => {
  console.error("Redis connection error:" , err);
});

module.exports = redis;
`
const configFolderPath = path.join(projectPath, 'config');
      fs.writeFileSync(path.join(configFolderPath, 'redis.js'), redisConfigContent);
      console.log('Generated config/redis.js');


// env for redis
const envContent = 
`REDIS_HOST=your-redis-host
REDIS_PORT=your-redis-port
REDIS_PASSWORD=your-redis-password

`;
  fs.appendFileSync(path.join(projectPath, '.env'), envContent);
  console.log('Generated .env file');


// constants/redisMessages
const redisMessagesContent =
`module.exports = {
  SET_CACHE_ERROR: 'Error setting cache for key:',
  GET_CACHE_ERROR: 'Error getting cache for key:',
  DELETE_CACHE_ERROR: 'Error deleting cache for key:',
  CACHE_SET_SUCCESS: 'Cache set for key:',
  CACHE_DELETED_SUCCESS: 'Cache deleted for key:',
};

`
const constantsFolderPath = path.join(projectPath, 'constants');
  fs.writeFileSync(path.join(constantsFolderPath, 'redisMessages.js'), redisMessagesContent);
  console.log('Generated constants/redisMessages.js');


// redis utility functions
const redisUtilsContent =
`const redis = require('../config/redis');
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


`
const utilsFolderPath = path.join(projectPath, 'utils');
  fs.writeFileSync(path.join(utilsFolderPath, 'redis-cache.js'), redisUtilsContent);
  console.log('Generated utils/redis-cache.js');

}


// redis-official implementation 
const implementRedisOfficial = () => {

  execSync('npm install redis ', { stdio: 'inherit' });
  console.log("redis installed successfully.");

  const redisConfigContent = 
`const redis = require('redis');

// Create a Redis client
const client = redis.createClient({
  host: process.env.REDIS_HOST || '127.0.0.1', 
  port: process.env.REDIS_PORT || 6379,      
  password: process.env.REDIS_PASSWORD || '', // Optional: For secured Redis
});

// Handle connection events
client.on('connect', () => {
  console.log('Connected to Redis!');
});

client.on('error', (err) => {
  console.error("Redis error:", err);
});

module.exports = client;
`
const configFolderPath = path.join(projectPath, 'config');
      fs.writeFileSync(path.join(configFolderPath, 'redis.js'), redisConfigContent);
      console.log('Generated config/redis.js');


// env for redis
const envContent = 
`REDIS_HOST=your-redis-host
REDIS_PORT=your-redis-port
REDIS_PASSWORD=your-redis-password

`;
  fs.appendFileSync(path.join(projectPath, '.env'), envContent);
  console.log('Generated .env file');


// constants/redisMessages
const redisMessagesContent =
`module.exports = {
  ERR_SET_CACHE: "Error setting cache for {key}:",
  ERR_GET_CACHE: "Error getting cache for {key}:",
  ERR_DEL_CACHE: "Error deleting cache for {key}:"
};

`
const constantsFolderPath = path.join(projectPath, 'constants');
  fs.writeFileSync(path.join(constantsFolderPath, 'redisMessages.js'), redisMessagesContent);
  console.log('Generated constants/redisMessages.js');


// redis utility functions
const redisUtilsContent =
`const client = require("../config/redis");
const { ERR_SET_CACHE, ERR_GET_CACHE, ERR_DEL_CACHE } = require("../constants/redisMessages.js");

// Function to set a key in Redis with an expiration time
const setCache = (key, value, ttl = 3600) => {
  client.setex(key, ttl, JSON.stringify(value), (err) => {
    if (err) {
      console.error(ERR_SET_CACHE.replace("{key}", key), err);
    }
  });
};

// Function to get a key from Redis
const getCache = (key, callback) => {
  client.get(key, (err, data) => {
    if (err) {
      console.error(ERR_GET_CACHE.replace("{key}", key), err);
      return callback(err, null);
    }
    return callback(null, JSON.parse(data));
  });
};

// Function to delete a key from Redis
const deleteCache = (key) => {
  client.del(key, (err) => {
    if (err) {
      console.error(ERR_DEL_CACHE.replace("{key}", key), err);
    }
  });
};

module.exports = { setCache, getCache, deleteCache };


`
const utilsFolderPath = path.join(projectPath, 'utils');
  fs.writeFileSync(path.join(utilsFolderPath, 'redis-cache.js'), redisUtilsContent);
  console.log('Generated utils/redis-cache.js');

}


program
  .name('backend-maker')
  .description('CLI to generate backend structure and snippets')
  .version('1.0.0');

// Initialize command
program
  .command('init')
  .description('Initialize a new backend project')
  .option('--mongodb', 'Include MongoDB configuration')
  .option('--mysql', 'Include MySQL configuration')
  .action((options) => {
    createBackendStructure();
    if (options.mongodb){ generateMongoDBConfig();
        installDependencies("mongodb");
    } // Include MongoDB if flag is passed
    if (options.mysql){ generateMySQLConfig(); 
        installDependencies("mysql2")
    }    // Include MySQL if flag is passed
    else{
        installDependencies();
    }
    createPackageJson(projectPath);
    // installDependencies();
    console.log('Backend structure generated successfully!');
});

//   .action(() => {
//     createBackendStructure();
//     createPackageJson(projectPath);
//     installDependencies();
//     console.log('Backend structure initialized successfully!');
//   });

// Add feature command
program
  .command('add <feature>')
  .description('Add optional features (e.g., api-rate-limiter,redis, docker, multer, cloudinary, email-sender, s3-aws-upload, mongodb, mysql)')
  .action((feature) => {
    if (feature.toLowerCase() === 'docker') {
      const dockerContent = `
FROM node:latest
WORKDIR /app
COPY package.json ./ 
RUN npm install
COPY . . 
EXPOSE 5000
CMD ["node", "app.js"]`;
      fs.writeFileSync('Dockerfile', dockerContent);
      console.log('Dockerfile added.');
    }
    else if (feature.toLowerCase() === 'mongodb') {
        console.log('Adding MongoDB configuration...');
        generateMongoDBConfig(); // Call the existing function
        installDependencies("mongodb");
    } 
    else if (feature.toLowerCase() === 'mysql' || feature.toLowerCase() === 'mysql2' || feature.toLowerCase() === 'mysql2-connection' || feature.toLowerCase() === 'mysql-connection' || feature.toLowerCase() === 'sequelize'){
        console.log('Adding MySQL configuration...');
        generateMySQLConfig(); // Call the existing function
        installDependencies("mysql2");
    }
    else if (feature.toLowerCase() === 'multer'){
        console.log('Adding Multer configuration...');
        generateMulterConfig(); 
    }
    else if (feature.toLowerCase() === 'api-rate-limiter' || feature.toLowerCase() === 'rate-limiter' || feature.toLowerCase() === 'api-rate-limiter-middleware'){
        console.log('Adding API rate limiter middleware...');
        generateRateLimiterMiddleware(); 
    }
    else if (feature.toLowerCase() === 'email-sender' || feature.toLowerCase() === 'email-sender-middleware' || feature.toLowerCase() === 'nodemailer'){
        console.log('Adding Nodemailer configuration...');
        generateEmailSender();
    }
    else if (feature.toLowerCase()==='s3-aws-upload' || feature.toLowerCase()==='s3-upload' || feature.toLowerCase()==='aws-s3-upload' || feature.toLowerCase()==='aws-s3' || feature.toLowerCase()==='aws-s3-config' || feature.toLowerCase()==='s3-aws' || feature.toLowerCase()==='s3'){
        console.log('Adding AWS S3 configuration...');
        generateS3Config();

    }
    else if (feature.toLowerCase() === 'redis' || feature.toLowerCase() === 'redis-cache' || feature.toLowerCase() === 'redis-config' || feature.toLowerCase() === 'ioredis'){
        console.log('Adding Redis...');
        // implementRedis();
      inquirer.prompt([
          {
            type: 'list',
            name: 'redisPackage',
            message: 'Which Redis package would you like to use? ',
            choices: ['redis (official): is lightweight and supports basic Redis operations efficiently.', 'ioredis: is feature-rich, supports cluster connections, and is better for advanced use cases.'],
          },
        ])
        .then((answers) => {
          if (answers.redisPackage === 'redis (official): is lightweight and supports basic Redis operations efficiently.') {
            console.log('Implementing Redis with the official redis package...');
            implementRedisOfficial(); 
          } 
          else{
            console.log('Implementing Redis with ioredis...');
            implementRedis(); 
          }
          });
    } 
    else if(feature.toLowerCase() === 'cloudinary'){
        console.log('Adding Cloudinary configuration...');
        generateCloudinaryConfig();
    }
    else {
      console.log(`Feature "${feature}" not recognized.`);
    }
  });

program.parse();

// const addCommand = program.commands.find((cmd) => cmd.name() === 'add');
// if (addCommand) {
//   console.log(`Description for 'add' command: ${addCommand.description()}`);
// }


