require("dotenv").config();
const jsonServer = require("json-server");
const server = jsonServer.create();
const router = jsonServer.router("src/database/db.json");
const middlewares = jsonServer.defaults();
const express = require("express");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");
const cors = require("cors");

const SECRET_KEY = process.env.SECRET_KEY;
const expiresIn = "8h";

server.use(express.json());
server.use(express.urlencoded({ extended: true }));
server.use(middlewares);
server.use(morgan("dev"));
server.use(cors());

function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

server.post("/auth/login", (req, res) => {
  const { email, password } = req.body;
  const userDB = router.db.get("users").find({ email }).value();

  if (!userDB || password !== userDB.password) {
    return res.status(401).json({ message: "Email or password is incorrect!" });
  }

  const token = createToken({ email: userDB.email, role: userDB.role });
  return res.status(200).json({
    message: "The user is authorized",
    token,
    user: { email: userDB.email, role: userDB.role },
  });
});

server.post("/auth/validateToken", (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ message: "The token is missing." });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);

    const userDB = router.db
      .get("users")
      .find({ email: decoded.email })
      .value();

    if (!userDB) {
      return res.status(404).json({ message: "User not found." });
    }

    const userResponse = {
      email: userDB.email,
      role: userDB.role,
    };

    return res.status(200).json(userResponse);
  } catch (error) {
    return res.status(401).json({ message: "The token is not valid." });
  }
});

server.post("/auth/logout", (req, res) => {
  res.status(200).send();
});

// Error handling middleware
server.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: "Something went wrong on the server." });
});

server.use(router);
const port = process.env.PORT || 5000;
server.listen(port, () => {
  console.log(`JSON Server is running on port ${port}`);
});
