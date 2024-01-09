import { MongoClient } from "mongodb";

import dotenv from "dotenv";

dotenv.config();

const mongodbConnectString = process.env.MONGODB_URL;

export const dbConnection = async () => {
  const client = new MongoClient(mongodbConnectString);
  client.connect();
  console.log("db connected successfully");
  return client;
};

export const client = await dbConnection();
