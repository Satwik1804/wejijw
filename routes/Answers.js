import express from "express";

import { postAnswer, deleteAnswer } from "../controllers/Answers.js";
import auth from "../middleware/auth.js";
import accessControl from "../middleware/accessControl.js";

const router = express.Router();

router.patch("/post/:id", accessControl, auth, postAnswer)
router.patch("/delete/:id", accessControl, auth, deleteAnswer) 

export default router