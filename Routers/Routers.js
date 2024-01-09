import express from "express";
import dotenv from "dotenv";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";
import bcrypt from "bcrypt";
import {
  allUsers,
  findUsers,
  addNewUser,
  generateToken,
  forgetPassword,
  ResetPassword,
} from "../dbcontrollers/dbControllers.js";
//-----------------------------imports-----------------------------------

const router = express.Router();
dotenv.config();

// ------------------------------------------Get all users-------------------------

// @route   GET all users info - users/all
router.get("/all", async (req, resp) => {
  const getallUsers = await allUsers({});

  if (getallUsers.length == 0) {
    return resp.status(400).json({ message: "No data available" });
  } else {
    resp.json({ data: getallUsers });
  }
});

// ------------------------------------------post new users-------------------------

// @route post New user (add)

router.post("/signup", async (req, resp) => {
  const userData = req.body; // data rec from post req from FE
  // check data was provided
  if (!userData) {
    return resp.json({ message: "no data provided" });
  }
  // check user exists in db
  const existingUser = await findUsers(userData.email);
  // if user does exists in db
  if (!existingUser) {
    // add the new user in db
    // salt value will be generated (1-10)
    const salt = await bcrypt.genSalt(10);
    // hashing the password + salt value
    const hashedPass = await bcrypt.hash(userData.password, salt);
    // {complete req.body, and in that password has the hashedpass will be stored}
    const userdata = await { ...userData, password: hashedPass };
    const newUser = await addNewUser(userdata);
    resp.json({ data: newUser });
  } else {
    resp.json({ message: "User aldready exists" });
  }
});

// ------------------------------------------ login existing users-------------------------

// @route post method login check

router.post("/login", async (req, resp) => {
  const userData = req.body;
  // check user exists in db
  const existingUser = await findUsers(userData.email);
  // if user doesn't exists in db
  if (!existingUser) {
    resp.json({ message: "user does not exists" });
  }
  // if user exists, validates for password which rec from user, and hashed pass stored in db
  const passValidation = await bcrypt.compare(
    userData.password,
    existingUser.password
  );
  //password doesn't match
  if (!passValidation) {
    resp.json({ message: "Invalid email or password" });
  }
  // if password matches and user credentials are valid --> token is generated from JWT
  const token = await generateToken(existingUser._id);
  // token will be sent to front end, & from FE we post with token,
  // need to compare the token we generated and we recieved are same
  resp.json({
    logedUserData: existingUser,
    generatedToken: token,
    loginStatus: "Sucessfully logged in",
  });
});
// ------------------------------------------ Forgot password for existing users-------------------------

// forgot password router

router.post("/forgotPassword", async (req, resp) => {
  const userData = req.body;
  // check user is an existing user
  // since email is unique, we check whether user is aldreay in
  const existingUser = await findUsers(userData.email);
  console.log(existingUser);
  // if user not found in db
  if (!existingUser) {
    resp.status(400).json({ message: "email id does not exists" });
  }
  // if user is found, token is generated from JWT expires in 1 day, and link will be sent to users gmail.
  const token = await forgetPassword(existingUser._id);
  // node mailer for genearting and sending link to the user...
  var transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.USERID,
      pass: process.env.PASSWORD,
    },
  });

  var mailOptions = {
    from: process.env.USERID,
    to: existingUser.email,
    subject: "StackOverflow Clone - Account recovery - Reset your password",
    text: `http://localhost:3000/users/PasswordRecovery/${existingUser._id}/${token}`,
  };

  transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      console.log(error);
    } else {
      console.log("Email sent: " + info.response); // return resp.send({ message: "success" });
    }
  });

  resp.json({ message: "Mail sent" });
});

// ------------------------------------------ Reset password for existing users-------------------------

//Reset password user

router.post("/PasswordRecovery/:id/:token", async (req, resp) => {
  // getting the id, and token from params when user clicks the link,
  const { id, token } = req.params;
  // new password is stored, as the user sets new password and sends it from FE post method
  const recievedPassword = req.body;
  // console.log(id, token, recievedPassword);
  // checking whether the token generated for the user using secret key is same, with the secret key we have..
  const isValid = jwt.verify(token, process.env.SECRET_KEY);
  //  console.log(isValid);

  if (!isValid) {
    resp.status(201).json({ Message: "invalid token" });
  }
  // salt value will be generated for the set new password (1-10)
  const salt = await bcrypt.genSalt(10);
  // hashing the new password  + new salt value
  const hashedPass = await bcrypt.hash(recievedPassword.password, salt);
  // {complete req.body, and in that password has the hashedpass}
  const userdata = { password: hashedPass };
  // password will be reset..
  const dbinfo = await ResetPassword(id, userdata); //sharing the info to db (saltv + hashed pass = new pass)

  return resp.status(201).json({ message: "password Changed successfully" });
});

// ------------------------------------------ End of routers-------------------------

export const userRouter = router;
