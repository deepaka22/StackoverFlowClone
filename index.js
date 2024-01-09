import express from "express";
import dotenv from "dotenv";
import { userRouter } from "./Routers/Routers.js";
import cors from "cors";
dotenv.config();
const app = express();
const port = process.env.PORT;

app.listen(port, () => {
  console.log(`server started successfully in ${port}`);
});
// middle ware..
app.use(cors());
app.use(express.json());
// routes...
app.use("/users", userRouter);
