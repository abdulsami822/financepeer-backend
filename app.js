const dotenv = require("dotenv");
dotenv.config();
const express = require("express");
var cors = require("cors");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(cors());

let db = null;
const dbFilePath = path.join(__dirname, "financepeer.db");

const initializeServer = async () => {
  try {
    db = await open({
      filename: dbFilePath,
      driver: sqlite3.Database,
    });
    app.listen(process.env.PORT, () => {
      console.log(`server is up and firing at ${process.env.PORT}`);
    });
  } catch (error) {
    console.log(`error is ${error.message}`);
    process.exit(1);
  }
};

initializeServer();

const getErrorMessage = (error) => {
  return { error_msg: error };
};

const checkUserDetails = (request, response, next) => {
  try {
    const userDetails = request.body;
    if (!userDetails) {
      throw new Error("Details are not provided");
    } else {
      const { username, email, password } = userDetails;
      if (!username) {
        throw new Error("username is required");
      } else if (!email) {
        throw new Error("email is required");
      } else if (!password) {
        throw new Error("password is required");
      }
    }
    next();
  } catch (error) {
    response.status(204);
    response.send(getErrorMessage(error.message));
  }
};

const passwordChecker = (request, response, next) => {
  try {
    const { password, confirmPassword } = request.body;
    if (!confirmPassword) {
      throw new Error("confirm password is not provided");
    } else if (password !== confirmPassword) {
      throw new Error("password and confirm password is not matching");
    } else if (password.length < 6) {
      throw new Error("password is too short");
    }
    next();
  } catch (error) {
    response.status(400);
    response.send(getErrorMessage(error.message));
  }
};

const checkUserCredentials = async (request, response, next) => {
  try {
    const { username, email, password } = request.body;
    const getUserQuery = `select * from user where username like '${username}'`;
    const user = await db.get(getUserQuery);
    if (!user) {
      throw new Error("User does not exist");
    } else if (user.email !== email) {
      throw new Error("Email is incorrect");
    } else if (!(await bcrypt.compare(password, user.password))) {
      throw new Error("Password is incorrect");
    }
    request.id = user.id;
    next();
  } catch (error) {
    response.status(401);
    response.send(getErrorMessage(error.message));
  }
};

const checkPostCredentials = (request, response, next) => {
  try {
    const file = request.body;
    const { user_id } = request.params;
    if (!file) {
      throw new Error("Data is required");
    } else {
      const authorization_header = request.headers["authorization"];
      if (!authorization_header) {
        throw new Error("Authorization Token is required");
      } else if (authorization_header.split(" ")[0] !== "Bearer") {
        throw new Error("Bearer Token is required");
      } else {
        const jwt_token = authorization_header.split(" ")[1];
        jwt.verify(jwt_token, process.env.SECRETKEY, (error, decoded) => {
          if (error) {
            throw new Error("Token is invalid");
          } else if (decoded.id != user_id) {
            throw new Error("user id in invalid");
          }
        });
      }
    }
    next();
  } catch (error) {
    response.status(403);
    response.send(getErrorMessage(error.message));
  }
};

app.post(
  "/user/register",
  checkUserDetails,
  passwordChecker,
  async (request, response) => {
    try {
      const userDetails = request.body;
      const { username, email, password } = userDetails;
      const hashedPassword = await bcrypt.hash(password, 10);
      const createUserQuery = `insert into user(email,username,password) values('${email}','${username}','${hashedPassword}')`;
      await db.run(createUserQuery);
      response.status(201);
      response.send({ message: "user successfully created" });
    } catch (error) {
      response.status(400);
      if (error.message.includes("email")) {
        response.send(getErrorMessage("email is already taken"));
      } else if (error.message.includes("username")) {
        response.send(getErrorMessage("username is already taken"));
      }
    }
  }
);

app.post(
  "/user/login",
  checkUserDetails,
  checkUserCredentials,
  async (request, response) => {
    try {
      const { username, email, password } = request.body;
      const id = request.id;
      const payload = {
        id,
        username,
        email,
      };
      const jwt_token = jwt.sign(payload, process.env.SECRETKEY);
      response.status(200);
      response.send({
        jwt_token,
        user: {
          id,
          username,
          email,
        },
      });
    } catch (error) {
      response.status(401);
      response.send(getErrorMessage(error.message));
    }
  }
);

app.post("/post/:user_id", checkPostCredentials, async (request, response) => {
  try {
    const { file } = request.body;
    const posts = JSON.parse(file);
    for (let i = 0; i < posts.length; i++) {
      const post = posts[i];
      const { title, id, body } = post;
      try {
        const user_id = post.userId;
        const insertQuery = `insert into post(id,user_id,title,body) values(${id},${user_id},'${title}','${body}')`;
        await db.run(insertQuery);
      } catch (error) {
        response.status(401);
        response.send(getErrorMessage(`post id ${id} is already taken`));
      }
    }
    response.status(201);
    response.send({ message: "Successfully uploaded File" });
  } catch (error) {
    response.status(401);
    response.send(getErrorMessage(error.message));
  }
});

app.get("/post/:user_id", checkPostCredentials, async (request, response) => {
  try {
    const query = `select * from post`;
    const data = await db.all(query);
    response.send({ post_data: data });
  } catch (error) {
    response.status(400);
    response.send(getErrorMessage(error.message));
  }
});
