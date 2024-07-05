import express from "express";

import { AskQuestion, getAllQuestions, deleteQuestion, voteQuestion } from "../controllers/Questions.js";
import auth from "../middleware/auth.js";
import accessControl from "../middleware/accessControl.js";

const router = express.Router();

router.post('/Ask', accessControl, auth, AskQuestion)
router.get('/get', accessControl, getAllQuestions)
router.delete('/delete/:id', accessControl, auth, deleteQuestion )
router.patch('/vote/:id', accessControl, auth, voteQuestion)

export default router;