import { client } from "../mongodb/db.js";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
import { ObjectId } from "mongodb";
dotenv.config();

export const allUsers = (req) => {
  return client.db("stackoverflow").collection("usersData").find(req).toArray();
};

export const findUsers = (req) => {
  return client
    .db("stackoverflow")
    .collection("usersData")
    .findOne({ email: req });
};

export const addNewUser = (newUser) => {
  return client.db("stackoverflow").collection("usersData").insertOne(newUser);
};

// Token is generated for login -->expires in 30d
export const generateToken = (id) => {
  return jwt.sign({ id }, process.env.SECRET_KEY, { expiresIn: "30d" });
};
// Token is generated for forget password -->expires in 1d
export const forgetPassword = (id) => {
  return jwt.sign({ id }, process.env.SECRET_KEY, { expiresIn: "1d" });
};

export const ResetPassword = (id, data) => {
  return client
    .db("stackoverflow")
    .collection("usersData")
    .findOneAndUpdate({ _id: new ObjectId(id) }, { $set: data });
};
