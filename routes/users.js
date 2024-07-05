import express from "express";

import { signup, login, forgotPasswordEmail, validateOTP, forgotPasswordSMS, createNewPassword, authenticateEmail, authenticateSMS, authenticateOTP, accessAuthentication, validateotp  } from "../controllers/auth.js";
import { getAllUsers, updateProfile, getLoginHistory } from "../controllers/users.js";
import auth from "../middleware/auth.js";
import accessControl from "../middleware/accessControl.js";

const router = express.Router();

router.post('/signup', accessControl, signup)
router.post("/login", accessControl, login)
router.patch('/forgotPasswordEmail', accessControl, forgotPasswordEmail)
router.patch('/forgotPasswordSMS', accessControl, forgotPasswordSMS)
router.patch('/validateOTP', accessControl, validateOTP)
router.patch('/setNewPassword', accessControl, createNewPassword)
router.patch('/authenticateEmail', accessControl, authenticateEmail)
router.patch('/authenticateSMS', accessControl, authenticateSMS)
router.patch('/authenticateOTP', accessControl, authenticateOTP)

router.get('/getAllUsers', accessControl, getAllUsers)
router.patch('/update/:id', accessControl, auth, updateProfile)

router.get('/getLoginHistory/:id', accessControl, getLoginHistory)

router.post('/accessAuthentication', accessAuthentication)
router.post('/validateotp', validateotp)

export default router;