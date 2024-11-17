#!/usr/bin/env node

const { Command } = require('commander');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

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
    const commonDependencies = ['express', 'jsonwebtoken', 'dotenv', 'cors', 'multer', 'bcryptjs', 'express-validator', 'nodemailer'];
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
    const folders = ['models', 'controllers', 'routes', 'middleware', 'utils', 'config', 'public'];
  
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
const connectDB = require('./config/db');
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
      trim: true,
      match: [/\S+@\S+\.\S+/, "Please use a valid email address"],
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

  if (!email || !/\S+@\S+\.\S+/.test(email)) {
    return res.status(400).json({ message: "A valid email is required" });
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

// Protected Route
router.get('/get/allUsers', authMiddleware, AuthController.getAllUsers);
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
MYSQL_URI=mysql://<username>:<password>@localhost:3306/mydb

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
    fs.writeFileSync(path.join(configFolderPath, 'dbMongo.js'), dbMongoContent);
    console.log('Generated config/dbMongo.js');
  };
  
  
  // generate Mysql config
const generateMySQLConfig = () => {
    const dbMysqlContent = 
`const { Sequelize } = require('sequelize');
const sequelize = new Sequelize(process.env.MYSQL_URI);
const connectDB = async () => {
    try {
        await sequelize.authenticate();
        console.log('MySQL Connected successfully.');
    } catch (err) {
        console.error('Unable to connect to the database:', err);
    }
};
module.exports = { sequelize, connectDB };`;
      const configFolderPath = path.join(projectPath, 'config');
      fs.writeFileSync(path.join(configFolderPath, 'dbMysql.js'), dbMysqlContent);
      console.log('Generated config/dbMysql.js');
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
  .description('Add optional features (e.g., api-rate-limiter, docker, multer, email-sender, s3, mongodb, mysql)')
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
    } 
    else if (feature.toLowerCase() === 'mysql') {
        console.log('Adding MySQL configuration...');
        generateMySQLConfig(); // Call the existing function
    }
    else if (feature.toLowerCase() === 'multer'){
        console.log('Adding Multer configuration...');
        generateMulterConfig(); 
    }
    else if (feature.toLowerCase() === 'api-rate-limiter'){
        console.log('Adding API rate limiter middleware...');
        generateRateLimiterMiddleware(); 
    }
    else if (feature.toLowerCase() === 'email-sender'){
        console.log('Adding Nodemailer configuration...');
        generateEmailSender();
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
