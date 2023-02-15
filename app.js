const express = require("express");
const basicAuth = require("express-basic-auth");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const { sequelize, User, UserToken } = require("./models");
const socketIo = require("socket.io");
const bcrypt = require('bcrypt');
const config = require('./config')

const morgan = require('morgan');
const path = require("path");
const { createWriteStream } = require("fs");
const rfs = require("rotating-file-stream");


const app = express();
app.use(bodyParser.json());
app.use(morgan('dev'));

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

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) {
    return res.sendStatus(401);
  }

  jwt.verify(token, "bingobaba777", (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }

    req.user = user;
    next();
  });
};

app.get("/", authenticateToken, (req, res) => {
  res.send(`Welcome ${req.user.email}!`);
});


app.post("/login", async (req, res) => {

  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });

  if (!user || !bcrypt.compareSync(password, user.password)) {
    res.status(401).send("Invalid credentials");
    return;
  }

  const user_id = user.id;
  const user_token_exists = await UserToken.findOne({ where: { user_id } });

  if (user_token_exists === null) {

    const accessToken = jwt.sign({ email }, "bingobaba777", { expiresIn: "1h" });
    const ip = req.ip;
    const newUserToken = await UserToken.create({ user_id, accessToken, ip });
    res.json({
      message: "Obtain New Successfully",
      accessToken
    });

  } else {

    try {
      const decodedToken = jwt.verify(user_token_exists.accessToken, "bingobaba777");

      // Check if the token has expired
      if (Date.now() >= decodedToken.exp * 1000) {
        // Token has expired, remove token record from the database
        await UserToken.destroy({ where: { user_id: user_token_exists.user_id } });

        res.status(401).json({ message: "Token has expired" });
        return;
      } else {

        await UserToken.destroy({ where: { user_id: user_token_exists.user_id } });
        const accessToken = jwt.sign({ email }, "bingobaba777", { expiresIn: "1h" });
        const ip = req.ip
        const newUserToken = await UserToken.create({ user_id, accessToken, ip });
        res.json({
          Message: "Renew Token Successfully",
          accessToken: user_token_exists.accessToken
        });

      }

    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {

        await UserToken.destroy({ where: { user_id: user_token_exists.user_id } });
        const accessToken = jwt.sign({ email }, "bingobaba777", { expiresIn: "1h" });
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
    console.log(password);
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
