const express = require("express");
const basicAuth = require("express-basic-auth");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const { sequelize, User } = require("./models");
const socketIo = require("socket.io");

const app = express();
app.use(bodyParser.json());

// home page
app.get("/", (req, res) => {
    res.send("Welcome to the home page");
  });
  
  // login page
  app.post("/login", (req, res) => {
    const { email, password } = req.body;
    
    console.log(password);

    const user = User.findOne({ where: { email } });
    if (!user || user.password !== password) {
      res.status(401).send("Invalid credentials");
      return;
    }
    const accessToken = jwt.sign({ email }, "secret");
    res.json({ accessToken });
  });
  
  // register page
  app.post("/register", (req, res) => {
    const { email, password } = req.body;
    User.create({ email, password });
    res.status(201).send("User created successfully");
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
  