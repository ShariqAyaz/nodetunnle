const express = require("express");
const basicAuth = require("express-basic-auth");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const { sequelize, User, UserToken } = require("./models");
const socketIo = require("socket.io");
const bcrypt = require('bcrypt');
const cors = require('cors');

const morgan = require('morgan');
const path = require("path");
const { createWriteStream } = require("fs");
const rfs = require("rotating-file-stream");

const app = express();
app.use(bodyParser.json());
app.use(morgan('dev'));
app.use(cors());

var salt = bcrypt.genSaltSync(14);


const accessLogStream = rfs.createStream("access.log", {
  interval: "1d", // rotate daily
  path: path.join(__dirname, "log"),
  size: "1M",
  compress: "gzip", // compress rotated files
  history: "access.log.%Y%m%d-%H%M%S", // keep up to 4 backup files
  maxFiles: 10, // maximum number of backup files
});

app.use(morgan("combined", { stream: accessLogStream }));

const errorLogStream = rfs.createStream('error.log', {
  interval: '1d',
  path: path.join(__dirname, 'log'),
  size: "1M",
  compress: 'gzip',
  maxFiles: 10,
});

const consoleLogStream = process.stdout;

const errorLogger = morgan('tiny', {
  stream: errorLogStream,
  skip: (req, res) => res.statusCode >= 400
});

// log errors to console and file
app.use(errorLogger);

let blacklistedTokens = new Set();

// Middleware to check if the user has a valid token
const checkToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    req.user = null;
    return next();
  }

  jwt.verify(token, process.env.SECRET_JWT, (err, user) => {
    if (err) {
      req.user = null;
      return next();
    }

    req.user = user;
    next();
  });
};

// Middleware to check if the user's token is blacklisted
const accessTokenExpirationTime = 60; // 1 hour in minutes

const checkTokenBlacklist = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token && blacklistedTokens.has(token)) {
    // Check if token has expired

    //blacklistedTokens.delete(token);
    req.user = null;

  }

  next();
};

// Route handler for the home page
app.get('/', checkToken, checkTokenBlacklist, async (req, res) => {

console.log(blacklistedTokens);


  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    // User is not authenticated
    
    res.json({
      message: `Welcome...! you are require to Login first <a href=${'/login'}>Login</a>`,
      links: {
        login: '/login',
      }
    });

  } else {

    const token = authHeader.split(" ")[1];

    if (!req.user) {
      // User is not authenticated
      const usertoken = await UserToken.findOne({ where: { accessToken: token } });
      if (usertoken) {

        if (usertoken.ip === req.ip) {

          UserToken.destroy({ where: { user_id: usertoken.user_id } });
          const user = await User.findOne({ where: { id: usertoken.user_id } });
          const email = user.email;
          const user_id = user.id;
          const accessToken = jwt.sign({ email }, process.env.SECRET_JWT, { expiresIn: "5m" });
          const ip = req.ip;
          const newUserToken = await UserToken.create({ user_id, accessToken, ip });
          res.json({
            message: "Obtain New After Expire",
            accessToken
          });
        } else {

          UserToken.destroy({ where: { user_id: oUserToken.user_id } });
          blacklistedTokens.add(oUserToken.accessToken);

          res.json({
            message: `Welcome Login Again <a href=${'/login'}>Login</a>`,
            links: {
              Reason: 'Logout, due to network changes',
              login: '/login',
            }
          });

        }

      } else {

        res.json({
          message: `Welcome...! Kindly Login Again. <a href=${'/login'}>Login</a>`,
          links: {
            login: '/login',
            Reason: 'Token is Retired, or blacklisted',
            usertoken: usertoken
          }
        });
  
      }

    } else if (blacklistedTokens.has(token)) {
      // User's token is blacklisted
      res.json({
        message: `Your session has expired. Please log in again.`,
        links: {
          login: '/login',
        }
      });
    } else {
      // User is authenticated and has a valid token
      const get_user = await User.findOne({ where: { email: req.user.email } });

      res.json({
        message: `Welcome ${get_user.username} | ${req.user.email}!`,
        links: {
          logout: '/logout',
          profile: '/profile'
        }
      });

    }

  }

});

// Route to renew the user's token
app.post("/renew-token", checkTokenBlacklist, (req, res) => {
  const { email } = req.body;
  const accessToken = jwt.sign({ email }, process.env.SECRET_JWT, { expiresIn: "5m" });
  res.json({ accessToken });
});

// logout
app.post("/logout", checkTokenBlacklist, async (req, res) => {

  const { email } = req.body;
  const oUser = await User.findOne({ where: { email } });

  const authHeader = req.headers["authorization"];
  
  if (!authHeader) {

    console.log(authHeader);
    
    // const token = authHeader.split(" ")[1];

    if (oUser !== null) {

      console.log("  NOT NULL 210  ");
      
      const user_id = oUser.id;
      const oUserToken = await UserToken.findOne({ where: { user_id } });

      if (oUserToken) {

        UserToken.destroy({ where: { user_id: oUserToken.user_id } });
        blacklistedTokens.add(oUserToken.accessToken);

      }
    }

  } else {

    const token = authHeader.split(" ")[1];
    const user_id = oUser.id;
    const oUserToken = await UserToken.findOne({ where: { user_id } });

    if (oUserToken) {

      UserToken.destroy({ where: { user_id: oUserToken.user_id } });
      blacklistedTokens.add(token);

    }else{
      blacklistedTokens.add(token);
    }
  }

  // const user_id = user.id;
  // const oUserToken = await UserToken.findOne({ where: { user_id } });

  // if (oUserToken) {
  //   UserToken.destroy({ where: { user_id: oUserToken.user_id } });

  //   blacklistedTokens.add(token);

  // }

  //console.log(blacklistedTokens);

  res.sendStatus(200);
});

app.post("/login", async (req, res) => {
  
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });

  if (!user || !bcrypt.compareSync(password, user.password)) {
    res.status(401).send("Invalid credentials");
    return;
  }

  const user_id = user.id;
  const oUserToken = await UserToken.findOne({ where: { user_id } });

  if (oUserToken === null) {

    const accessToken = jwt.sign({ email }, process.env.SECRET_JWT, { expiresIn: "5m" });
    const ip = req.ip;
    const newUserToken = await UserToken.create({ user_id, accessToken, ip });

    // req.session.accessToken.maxAge = 30 * 24 * 60 * 60 * 1000;
    // res.cookie('accessToken', accessToken, { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true });

    res.json({
      message: "Obtain New Successfully",
      accessToken
    });

  } else {

    try {
      const decodedToken = jwt.verify(oUserToken.accessToken, process.env.SECRET_JWT);

      // Check if the token has expired
      if (Date.now() >= decodedToken.exp * 1000) {
        // Token has expired, remove token record from the database
        blacklistedTokens.add(oUserToken.accessToken);
        await UserToken.destroy({ where: { user_id: oUserToken.user_id } });

        res.status(401).json({ message: "Token has expired" });
        return;
      } else {
        

        blacklistedTokens.add(oUserToken.accessToken);
        await UserToken.destroy({ where: { user_id: oUserToken.user_id } });
        const accessToken = jwt.sign({ email }, process.env.SECRET_JWT, { expiresIn: "5m" });
        const ip = req.ip
        const newUserToken = await UserToken.create({ user_id, accessToken, ip });
        res.json({
          Message: "Renew Token Successfully",
          accessToken: oUserToken.accessToken
        });

      }

    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {

        await UserToken.destroy({ where: { user_id: oUserToken.user_id } });
        const accessToken = jwt.sign({ email }, process.env.SECRET_JWT, { expiresIn: "5m" });
        const ip = req.ip
        const newUserToken = await UserToken.create({ user_id, accessToken, ip });
        res.json({
          accessToken,
          message: "Token has expired | Renew Token Successfully"
        });

      } else res.status(401).json({ message: "Invalid token" });

    }

  }

});

app.post("/register", async (req, res) => {

  const { username, email, password } = req.body;
  const p = password;
  try {

    const password = bcrypt.hashSync(p, salt);

    const newUser = await User.create({ username, email, password });

    res.status(201).send("User created successfully");

  } catch (error) {

    if (error.name === "SequelizeValidationError") {
      // handle validation errors
      res.status(400).send(error.errors.map((e) => e.message));
    } else if (error.name === "SequelizeUniqueConstraintError") {
      // handle other errors
      console.error(error);
      res.status(200).send("Duplicate constraint");
    } else {
      console.error(error);
      res.status(500).send("Internal Server Error");
    }

  }

});


app.get("/users", async (req, res) => {
  try {
    const users = await User.findAll();
    res.send(users);
  } catch (error) {
    console.error(error);
    res.status(500).send("Error fetching users from the database");
  }
});

// family page
app.get("/group/Family", (req, res) => {
  res.send("Welcome to the Family group page");
});


const server = app.listen(3000, () => {
  console.log("Server started on port 3000");
});
