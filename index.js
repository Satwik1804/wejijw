import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import dotenv from "dotenv";

import userRoutes from "./routes/users.js";
import questionRoutes from "./routes/Questions.js";
import answerRoutes from "./routes/Answers.js";
import tagsListRoutes from "./routes/tags.js"

dotenv.config()

const app = express();

app.use(express.json({limit: "30mb", extended: "true"}))
app.use(express.urlencoded({limit: "30mb", extended: "true"}))
app.use(cors())

app.get("/", (req, res) => {
    res.send("This is a stack overflow clone API")
})

app.use("/user" , userRoutes);
app.use("/questions", questionRoutes)
app.use("/answers", answerRoutes)
app.use("/tags", tagsListRoutes)

const PORT = process.env.PORT || 5000

const CONNECTION_URL = process.env.MONGO_URI

mongoose.connect(CONNECTION_URL)
   .then(() => app.listen(PORT, () => { console.log(`server running on port ${PORT}`) }))
   .catch((err) => console.log(err.message))