const express = require("express");
const basicAuth = require("express-basic-auth");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const { sequelize, User } = require("./models");
const socketIo = require("socket.io");
const bcrypt = require('bcrypt');


const app = express();
app.use(bodyParser.json());
var salt = bcrypt.genSaltSync(14);

// home page
app.get("/", (req, res) => {
  res.send("Welcome to the home page");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ where: { email } });

  if (!user || !bcrypt.compareSync(password, user.password)) {
    res.status(401).send("Invalid credentials");
    return;
  }

  const accessToken = jwt.sign({ email }, "bingobaba777");
  res.json({ accessToken });
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

// users page
// app.get("/users", basicAuth({
//   authorizer: (username, password) => {
//     const user = User.findOne({ where: { email: username } });
//     if (!user || user.password !== password) {
//       return false;
//     }
//     return true;
//   },
//   authorizeAsync: true
// }), (req, res) => {
//   const users = User.findAll();
//   res.json(users);
// });

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
