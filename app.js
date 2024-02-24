const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
const { connectToDb, getDb } = require('./db');
const { ObjectId } = require("mongodb");

const app = express();
app.use(express.json());
app.use(cors());

let db;

// Define middleware to authenticate token
const authenticateToken = async (request, response, next) => {
  try {
    const authHeader = request.headers["authorization"];
    const jwtToken = authHeader ? authHeader.split(" ")[1] : undefined;

    if (!jwtToken) {
      return response.status(401).send("Invalid JWT Token");
    }

    const payload = await jwt.verify(jwtToken, process.env.JWT_SECRET || "defaultSecret");
    request.email = payload.email;
    next();
  } catch (error) {
    console.error("Error in authentication middleware:", error);
    response.status(401).send("Unauthorized");
  }
};

// Connect to database and start the server
connectToDb((err) => {
  if (err) {
    console.error('Error connecting to database:', err);
    return;
  }
  db = getDb();
  app.listen(3001, () => {
    console.log(`App is listening on port 3001`);
  });
});

// Define routes after ensuring db is properly initialized
app.get("/profile/", authenticateToken, async (request, response) => {
  try {
    const { email } = request;
    const userCollection = db.collection("user");
    const userDetails = await userCollection.findOne({ email });

    if (userDetails) {
      response.send(userDetails);
    } else {
      response.status(404).send("User not found");
    }
  } catch (error) {
    console.error("Error in /profile/ route:", error);
    response.status(500).send("Internal Server Error");
  }
});

app.post("/users/", async (request, response) => {
  try {
    const { username, name, password, email,Phonenumber } = request.body;

    const userCollection = db.collection("user");
    const existingUser = await userCollection.findOne({ username });

    if (!existingUser) {
      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = {
        username,
        name,
        password: hashedPassword,
        email,
        Phonenumber
      };

      await userCollection.insertOne(newUser);

      response.send("User created successfully");
    } else {
      response.status(400).send("User already exists");
    }
  } catch (error) {
    console.error("Error in /users/ route:", error);
    response.status(500).send("Internal Server Error");
  }
});

app.post("/login", async (request, response) => {
  try {
    const { email, password } = request.body;

    const userCollection = db.collection("user");
    const user = await userCollection.findOne({ email });

    if (!user) {
      response.status(400).send("Invalid User");
    } else {
      const isPasswordMatched = await bcrypt.compare(password, user.password);

      if (isPasswordMatched) {
        const payload = { email };
        const jwtToken = jwt.sign(payload, process.env.JWT_SECRET || "defaultSecret");
        response.send({ jwtToken });
      } else {
        response.status(400).send("Invalid Password");
      }
    }
  } catch (error) {
    console.error("Error in /login route:", error);
    response.status(500).send("Internal Server Error");
  }
});