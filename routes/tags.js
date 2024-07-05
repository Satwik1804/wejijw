import express from "express";

import { getTagsList, getAllTags } from "../controllers/tags.js";
import accessControl from "../middleware/accessControl.js";

const router = express.Router();

router.get('/getTagsList', accessControl, getTagsList)

router.get("/getAllTags", accessControl, getAllTags)

export default router;