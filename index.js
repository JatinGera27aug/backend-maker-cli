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
    const commonDependencies = ['express', 'jsonwebtoken', 'dotenv', 'cors', 'nodemon', 'bcrypt', 'express-validator'];
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
    const folders = ['models', 'controllers', 'routes', 'middleware', 'utils', 'config', 'public', 'constants'];
  
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
// const connectDB = require('./config/dbMongo.js');  // provide db url in .env file
// connectDB();

// const sampleRoutes = require('./routes/sampleRoutes.js')

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
  console.log('Generated routes/sampleRoutes.js');



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


// adding passport js functionality
const implementPassportLocal = () => {
  execSync('npm install passport express-session passport-local', { stdio: 'inherit' });
  console.log("passport installed successfully.");

  const passportMiddlewareContent = 
`const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const Demo = require("../models/Demo"); // Replace with your Model
const session = require("express-session");

/**
 * Configure Passport Local Strategy
 */
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await Demo.findOne({ username });
      if (!user) return done(null, false, { message: "User not found" });

      if (!user.password == password) return done(null, false, { message: "Incorrect password" });
    
      // If user is found and password is correct, return user
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

// Serialize user ID into session
passport.serializeUser((user, done) => done(null, user.id));

// Deserialize user from ID stored in session
passport.deserializeUser(async (id, done) => {
  try {
    const user = await Demo.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

/**
 * Middleware to initialize Passport and session
 */
const initializePassportSession = (app) => {    // replace app with your express instance
  app.use(
    session({
      secret: process.env.SESSION_SECRET || "default_secret",
      resave: false,
      saveUninitialized: false,
    })
  );
  app.use(passport.initialize());
  app.use(passport.session());
};

// Middleware to protect routes
 
const isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).send("Unauthorized");
};

module.exports = { initializePassportSession, isAuthenticated };

`

const middlewareFolderPath = path.join(projectPath, 'middleware');
  fs.writeFileSync(path.join(middlewareFolderPath, 'passport-local.js'), passportMiddlewareContent);
  console.log('Generated middleware/passport-local.js');
}


// adding passport-google
const implementPassportGoogle = () => {
  execSync('npm install passport express-session passport-google-oauth20', { stdio: 'inherit' });
  console.log("passport installed successfully.");

  const passportMiddlewareContent = 
`const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
require("dotenv").config();

// configuration to be done in .env file
const configureGooglePassport = () => {
    const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
    const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
    const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "http://localhost:8000/auth/google/callback";

    passport.use(
        new GoogleStrategy(
            {
                clientID: GOOGLE_CLIENT_ID,
                clientSecret: GOOGLE_CLIENT_SECRET,
                callbackURL: GOOGLE_CALLBACK_URL,
            },
            async (accessToken, refreshToken, profile, done) => {
                // Save user profile to database here, if needed
                // Example: const user = await User.findOrCreate({ googleId: profile.id });
                return done(null, profile);
            }
        )
    );

    passport.serializeUser((user, done) => {
        done(null, user);
    });

    passport.deserializeUser((user, done) => {
        done(null, user);
    });
};


const initializeGoogleAuth = (app) => {
    const session = require("express-session");

    app.use(
        session({
            secret: process.env.SESSION_SECRET || "default_secret",
            resave: false,
            saveUninitialized: false,
        })
    );
    app.use(passport.initialize());
    app.use(passport.session());
};

module.exports = { configureGooglePassport, initializeGoogleAuth, passport };


`

const middlewareFolderPath = path.join(projectPath, 'middleware');
  fs.writeFileSync(path.join(middlewareFolderPath, 'passport-google.js'), passportMiddlewareContent);
  console.log('Generated middleware/passport-google.js');


const google_OAuth_RoutesContent = 
`const express = require("express");
const { passport } = require("../middleware/passport-google");

const router = express.Router();

// Login with Google
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

// Google OAuth callback
router.get(
    "/google/callback",
    passport.authenticate("google", { failureRedirect: "/" }),
    (req, res) => {
        res.redirect("/profile");
    }
);

// Profile route (protected)
router.get("/profile", (req, res) => {
    if (req.isAuthenticated()) {
        res.send("Welcome", req.user.displayName);
    } else {
        res.redirect("/");
    }
});

// Logout route
router.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error("Logout error:", err);
            return res.status(500).send("Error logging out");
        }
        res.redirect("/");
    });
});

module.exports = router;

`

const RoutesFolderPath = path.join(projectPath, 'routes');
  fs.writeFileSync(path.join(RoutesFolderPath, 'Google-0Auth-SampleRoutes.js'), google_OAuth_RoutesContent);
  console.log('Generated routes/Google-0Auth-SampleRoutes.js');


// env content
const envContent = 
`GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=http://localhost:8000/auth/google/callback
SESSION_SECRET=your-session-secret

`;
  fs.appendFileSync(path.join(projectPath, '.env'), envContent);
  console.log('Generated .env file');

}

// adding passport-FaceBook
const implementPassportFacebook = () => {

  // Install dependencies
  execSync('npm install passport express-session passport-facebook', { stdio: 'inherit' });
  console.log("Passport-Facebook installed successfully.");

  // Middleware content for Passport-Facebook
  const facebookMiddlewareContent = 
`const passport = require("passport");
const FacebookStrategy = require("passport-facebook").Strategy;
require("dotenv").config();

const configureFacebookPassport = () => {
    const FACEBOOK_APP_ID = process.env.FACEBOOK_APP_ID;
    const FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET;
    const FACEBOOK_CALLBACK_URL = process.env.FACEBOOK_CALLBACK_URL || "http://localhost:8000/auth/facebook/callback";

    passport.use(
        new FacebookStrategy(
            {
                clientID: FACEBOOK_APP_ID,
                clientSecret: FACEBOOK_APP_SECRET,
                callbackURL: FACEBOOK_CALLBACK_URL,
                profileFields: ["id", "emails", "name"], // Request additional fields if needed
            },
            async (accessToken, refreshToken, profile, done) => {
                // Save user profile to database here, if needed
                return done(null, profile);
            }
        )
    );

    passport.serializeUser((user, done) => {
        done(null, user);
    });

    passport.deserializeUser((user, done) => {
        done(null, user);
    });
};

const initializeFacebookAuth = (app) => {
    const session = require("express-session");

    app.use(
        session({
            secret: process.env.SESSION_SECRET || "default_secret",
            resave: false,
            saveUninitialized: false,
        })
    );
    app.use(passport.initialize());
    app.use(passport.session());
};

module.exports = { configureFacebookPassport, initializeFacebookAuth, passport };
`;

  const middlewareFolderPath = path.join(process.cwd(), 'middleware');
  if (!fs.existsSync(middlewareFolderPath)) {
    fs.mkdirSync(middlewareFolderPath);
  }
  fs.writeFileSync(path.join(middlewareFolderPath, 'passport-facebook.js'), facebookMiddlewareContent);
  console.log('Generated middleware/passport-facebook.js');

  // Routes content for Facebook OAuth
  const facebookOAuthRoutesContent = 
`const express = require("express");
const { passport } = require("../middleware/passport-facebook");

const router = express.Router();

// Login with Facebook
router.get("/facebook", passport.authenticate("facebook", { scope: ["email"] }));

// Facebook OAuth callback
router.get(
    "/facebook/callback",
    passport.authenticate("facebook", { failureRedirect: "/" }),
    (req, res) => {
        res.redirect("/profile");
    }
);

// Profile route (protected)
router.get("/profile", (req, res) => {
    if (req.isAuthenticated()) {
        res.send("Welcome", req.user.displayName || req.user.name.givenName);
    } else {
        res.redirect("/");
    }
});

// Logout route
router.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error("Logout error:", err);
            return res.status(500).send("Error logging out");
        }
        res.redirect("/");
    });
});

module.exports = router;
`;

  const routesFolderPath = path.join(process.cwd(), 'routes');
  if (!fs.existsSync(routesFolderPath)) {
    fs.mkdirSync(routesFolderPath);
  }
  fs.writeFileSync(path.join(routesFolderPath, 'Facebook-Auth-SampleRoutes.js'), facebookOAuthRoutesContent);
  console.log('Generated routes/Facebook-Auth-SampleRoutes.js');

  // .env content for Facebook
  const envContent = 
`FACEBOOK_APP_ID=your-facebook-app-id
FACEBOOK_APP_SECRET=your-facebook-app-secret
FACEBOOK_CALLBACK_URL=http://localhost:8000/auth/facebook/callback
SESSION_SECRET=your-session-secret

`;
  fs.appendFileSync(path.join(process.cwd(), '.env'), envContent);
  console.log('Generated .env file');
};


// adding passport-GITHUB 
const implementPassportGitHub = () => {
  // Install dependencies
  execSync('npm install passport express-session passport-github2', { stdio: 'inherit' });
  console.log("Passport-GitHub installed successfully.");

  // Middleware content for Passport-GitHub
  const githubMiddlewareContent = 
`const passport = require("passport");
const GitHubStrategy = require("passport-github2").Strategy;
require("dotenv").config();

const configureGitHubPassport = () => {
    const GITHUB_CLIENT_ID = process.env.GITHUB_CLIENT_ID;
    const GITHUB_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
    const GITHUB_CALLBACK_URL = process.env.GITHUB_CALLBACK_URL || "http://localhost:8000/auth/github/callback";

    passport.use(
        new GitHubStrategy(
            {
                clientID: GITHUB_CLIENT_ID,
                clientSecret: GITHUB_CLIENT_SECRET,
                callbackURL: GITHUB_CALLBACK_URL,
            },
            async (accessToken, refreshToken, profile, done) => {
                // Save user profile to database here, if needed
                return done(null, profile);
            }
        )
    );

    passport.serializeUser((user, done) => {
        done(null, user);
    });

    passport.deserializeUser((user, done) => {
        done(null, user);
    });
};

const initializeGitHubAuth = (app) => {
    const session = require("express-session");

    app.use(
        session({
            secret: process.env.SESSION_SECRET || "default_secret",
            resave: false,
            saveUninitialized: false,
        })
    );
    app.use(passport.initialize());
    app.use(passport.session());
};

module.exports = { configureGitHubPassport, initializeGitHubAuth, passport };
`;

  const middlewareFolderPath = path.join(process.cwd(), 'middleware');
  if (!fs.existsSync(middlewareFolderPath)) {
    fs.mkdirSync(middlewareFolderPath);
  }
  fs.writeFileSync(path.join(middlewareFolderPath, 'passport-github.js'), githubMiddlewareContent);
  console.log('Generated middleware/passport-github.js');

  // Routes content for GitHub OAuth
  const githubOAuthRoutesContent = 
`const express = require("express");
const { passport } = require("../middleware/passport-github");

const router = express.Router();

// Login with GitHub
router.get("/github", passport.authenticate("github", { scope: ["user:email"] }));

// GitHub OAuth callback
router.get(
    "/github/callback",
    passport.authenticate("github", { failureRedirect: "/" }),
    (req, res) => {
        res.redirect("/profile");
    }
);

// Profile route (protected)
router.get("/profile", (req, res) => {
    if (req.isAuthenticated()) {
        res.send("Welcome", req.user.username);
    } else {
        res.redirect("/");
    }
});

// Logout route
router.get("/logout", (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error("Logout error:", err);
            return res.status(500).send("Error logging out");
        }
        res.redirect("/");
    });
});

module.exports = router;
`;

  const routesFolderPath = path.join(process.cwd(), 'routes');
  if (!fs.existsSync(routesFolderPath)) {
    fs.mkdirSync(routesFolderPath);
  }
  fs.writeFileSync(path.join(routesFolderPath, 'GitHub-Auth-SampleRoutes.js'), githubOAuthRoutesContent);
  console.log('Generated routes/GitHub-Auth-SampleRoutes.js');

  // .env content for GitHub
  const envContent = 
`GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_CALLBACK_URL=http://localhost:8000/auth/github/callback
SESSION_SECRET=your-session-secret

`;
  fs.appendFileSync(path.join(process.cwd(), '.env'), envContent);
  console.log('Generated .env file');
};





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
  .description('Add optional features (e.g., api-rate-limiter, redis, docker, passport.js(local, google, github, facebook), multer, cloudinary, email-sender, s3-aws-upload, mongodb, mysql)')
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
    else if (feature.toLowerCase() === 'passport.js' || feature.toLowerCase() === 'passport-local' || feature.toLowerCase() === 'passport'){
      console.log('Adding Passport.js...');
      // implementRedis();
    inquirer.prompt([
        {
          type: 'list',
          name: 'Passport_js_Providers',
          message: 'Which Passport js provider would you like to use? ',
          choices: ['passport-google', 'passport-local', 'passport-facebook','passport-github'],
        },
      ])
      .then((answers) => {
        if (answers.Passport_js_Providers === 'passport-local') {
          console.log('adding middlewares for passport-local');
          implementPassportLocal(); 
        } 
        else if( answers.Passport_js_Providers === 'passport-google'){
          console.log('adding middlewares and Sample Routes for passport-google');
          implementPassportGoogle();
        }
        else if( answers.Passport_js_Providers === 'passport-facebook'){
          console.log('adding middlewares and Sample Routes for passport-facebook');
          implementPassportFacebook();
        }
        else if( answers.Passport_js_Providers === 'passport-github'){
          console.log('adding middlewares and Sample Routes for passport-github');
          implementPassportGitHub();
        }
        else{
          console.log('adding middleware for passport-google')
        }
        });
   } 
    else if(feature.toLowerCase() === 'passport-google'){
        console.log('adding middlewares and Sample Routes for passport-google');
        implementPassportGoogle();
    }
    else if(feature.toLowerCase() === 'passport-facebook'){
        console.log('adding middlewares and Sample Routes for passport-facebook');
        implementPassportFacebook();
    }
    else if(feature.toLowerCase() === 'passport-github'){
      console.log('adding middlewares and Sample Routes for passport-github');
      implementPassportGitHub();
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




