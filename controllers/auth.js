import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";
import twilio from "twilio";
import NodeCache from "node-cache";
import dotenv from "dotenv";
import UAParser from "ua-parser-js";

import users from "../models/auth.js";

dotenv.config()

const myCache = new NodeCache({ stdTTL: parseInt(process.env.TTL) });

const transporter = nodemailer.createTransport({
    service: 'Gmail',
    auth: {
        user: process.env.USER, 
        pass: process.env.PASSWORD  
    }
});

const accountSid = process.env.SID;
const authToken = process.env.TOKEN;
const client = twilio(accountSid, authToken);

const sendSMS = async (to, from, body) => {
    try {
        const message = await client.messages.create({
            body: body,
            from: from,
            to: to
        });
    } catch (error) {
        console.error('Error sending SMS:', error);
    }
};

export const signup = async (req, res) => {
    const { name, email, password, phoneNumber } = req.body;
    try {
        const existingUser = await users.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "User already exists with this email." });
        }
        const anotherExistingUser = await users.findOne({ phoneNumber });
        if (anotherExistingUser) {
            return res.status(400).json({ message: "User already exists with this phone number." });
        }
        const hashedPassword = await bcrypt.hash(password, parseInt(process.env.HASH));
        const userAgentString = req.headers['user-agent'];
        const parser = new UAParser();
        const agent = parser.setUA(userAgentString).getResult();

        const newUser = await users.create({ name, email, password: hashedPassword, phoneNumber });
        const signupInfo = {
            loginTime: new Date(),
            ipAddress: req.ip,
            browser: agent.browser.name + ' ' + agent.browser.version,
            os: agent.os.name + ' ' + agent.os.version,
            device: (agent.device.vendor || 'Other') + ' ' + (agent.device.model || 'Other') + ' ' + (agent.device.type || 'Other')
        };
        newUser.loginHistory.push(signupInfo);

        await newUser.save();

        const token = jwt.sign({ email: newUser.email, id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(201).json({ result: newUser, token });
    } catch (error) {
        console.error("Error signing up:", error);
        res.status(500).json({ message: "Something went wrong..." });
    }
};


export const login = async (req, res) => {
    const { email, password } = req.body;
    try {
        const existingUser = await users.findOne({ email });
        if (!existingUser) {
            return res.status(404).json({ message: "User doesn't exist." });
        }
        const isPasswordCorrect = await bcrypt.compare(password, existingUser.password);
        if (!isPasswordCorrect) {
            return res.status(400).json({ message: "Invalid credentials." });
        }
        const userAgentString = req.headers['user-agent'];
        const parser = new UAParser();
        const agent = parser.setUA(userAgentString).getResult();

        existingUser.loginHistory.pop();
        const loginInfo = {
            loginTime: new Date(),
            ipAddress: req.ip,
            browser: agent.browser.name + ' ' + agent.browser.version,
            os: agent.os.name + ' ' + agent.os.version,
            device: (agent.device.vendor || 'Other') + ' ' + (agent.device.model || 'Other') + ' ' + (agent.device.type || 'Other')
        };
        existingUser.loginHistory.push(loginInfo);

        await existingUser.save();

        const token = jwt.sign({ email: existingUser.email, id: existingUser._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.status(200).json({ result: existingUser, token });
    } catch (error) {
        res.status(500).json({ message: "Something went wrong..." });
    }
};


export const forgotPasswordEmail = async (req, res) => {
    const { email } = req.body;
    try {
        let user = await users.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "User doesn't exist" });
        }

        const OTP = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = OTP;
        user.otpExpires = Date.now() + 300000;
        await user.save();

        const mailOptions = {
            from: process.env.USER,
            to: email,
            subject: 'Password Reset Request for Your Stack Overflow Account',
            html: `
                <p>Hello,</p>
                <p>We received a request to reset the password for your Stack Overflow account.</p>
                <p>Please use the following OTP (One-Time Password) to reset your password:</p>
                <h3>${OTP}</h3>
                <p>This OTP is valid for 5 minutes. If you did not request this password reset, you can safely ignore this email.</p>
                <p>Thank you,</p>
                <p>The Stack Overflow Team</p>
            `
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(500).json({ message: 'Failed to send email' });
            } else {
                res.status(200).json({ message: 'Email sent successfully!', OTP });
            }
        });
    } catch (error) {
        res.status(500).json({ message: "Something went wrong..." });
    }
};

export const forgotPasswordSMS = async (req, res) => {
    const { phoneNumber } = req.body;  
    try {
        let user = await users.findOne({ phoneNumber });
        if (!user) {
            return res.status(400).json({ message: "User doesn't exist" });
        }

        const OTP = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = OTP;
        user.otpExpires = Date.now() + 300000;
        await user.save();

        const fromPhoneNumber = process.env.PHONE;  
        const messageBody = `Your password reset code is: ${OTP}`;  

        await sendSMS("+91" + phoneNumber, fromPhoneNumber, messageBody);
        res.status(200).json({ message: "OTP sent successfully" });
    } catch (error) {
        res.status(500).json({ message: "Something went wrong" });
    }
};

export const validateOTP = async(req, res) => {
    const { otp } = req.body;
    try {
        const user = await users.findOne({ otp, otpExpires: { $gt: Date.now() } });
        if (!user) {
            return res.status(400).json({ message: "Invalid OTP or OTP has expired" });
        }
        user.otp = undefined;
        user.otpExpires = undefined;
        await user.save();
        res.status(200).json({ message: "OTP validated successfully" });
    } catch (error) {
        res.status(500).json({ message: "Something went wrong" });
    }
};

export const createNewPassword = async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await users.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "User doesn't exist" });
        }
        const hashedPassword = await bcrypt.hash(password, parseInt(process.env.HASH));
        user.password = hashedPassword;
        await user.save();

        const mailOptions = {
            from: process.env.USER,
            to: email,
            subject: 'Password Updated Successfully',
            html: `
              <p>Hello ${user.name},</p>
              <p>Your password has been successfully updated.</p>
              <p>If you did not make this change, please contact support immediately.</p>
              <p>Thank you,</p>
              <p>The Stack Overflow Team</p>
            `
          };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(500).json({ message: 'Failed to send email' });
            } else {
                res.status(200).json({ message: 'Password updated successfully!' });
            }
        });
    } catch (error) {
        res.status(500).json({ message: "Something went wrong" });
    }
};

export const authenticateEmail = async (req, res) => {
    const { email } = req.body;
    try {
        const user = await users.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: "User doesn't exist" });
        }
        const OTP = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = OTP;
        user.otpExpires = Date.now() + 300000;
        await user.save();

        const mailOptions = {
            from: process.env.USER,
            to: email,
            subject: 'OTP for language change Your Stack Overflow Account',
            html: `
                <p>Hello,</p>
                <p>We received a request to reset the password for your Stack Overflow account.</p>
                <p>Please use the following OTP (One-Time Password) to change language:</p>
                <h3>${OTP}</h3>
                <p>This OTP is valid for 5 minutes. If you did not request this language change, you can safely ignore this email.</p>
                <p>Thank you,</p>
                <p>The Stack Overflow Team</p>
            `
          };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(500).json({ message: 'Failed to send email' });
            } else {
                res.status(200).json({ message: 'OTP sent successfully!' });
            }
        });
    } catch (error) {
        res.status(500).json({ message: "Something went wrong" });
    }
}

export const authenticateSMS = async (req, res) => {
    const { phoneNumber } = req.body;  
    try {
        let user = await users.findOne({ phoneNumber });
        if (!user) {
            return res.status(400).json({ message: "User doesn't exist" });
        }

        const OTP = Math.floor(100000 + Math.random() * 900000).toString();
        user.otp = OTP;
        user.otpExpires = Date.now() + 300000;
        await user.save();

        const fromPhoneNumber = process.env.PHONE;  
        const messageBody = `Your OTP for language change is: ${OTP}`;  

        await sendSMS("+91" + phoneNumber, fromPhoneNumber, messageBody);
        res.status(200).json({ message: "OTP sent successfully" });
    } catch (error) {
        res.status(500).json({ message: "Something went wrong" });
    }
};

export const authenticateOTP = async(req, res) => {
    const { otp, lang } = req.body;
    try {
        const user = await users.findOne({ otp, otpExpires: { $gt: Date.now() } });
        if (!user) {
            return res.status(400).json({ message: "Invalid OTP or OTP has expired" });
        }
        user.otp = undefined;
        user.otpExpires = undefined;
        user.lang = lang;
        await user.save();
        res.status(200).json({ message: "OTP validated successfully" });
    } catch (error) {
        res.status(500).json({ message: "Something went wrong" });
    }
};

export const accessAuthentication = async (req, res) => {
    const { email } = req.body;
    try {
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      myCache.set(email, otp); 
  
      const mailOptions = {
        from: process.env.USER,
        to: email,
        subject: 'OTP for accessing Your Stack Overflow Account',
        html: `
          <p>Hello,</p>
          <p>We received a request to access your Stack Overflow account.</p>
          <p>Please use the following OTP (One-Time Password) to access our website:</p>
          <h3>${otp}</h3>
          <p>This OTP is valid for 5 minutes. If you did not request this access, you can safely ignore this email.</p>
          <p>Thank you,</p>
          <p>The Stack Overflow Team</p>
        `,
      };
  
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          return res.status(500).json({ message: 'Failed to send email' });
        } else {
          return res.status(200).json({ message: 'OTP sent successfully!' });
        }
      });
    } catch (error) {
      res.status(500).json({ message: "Something went wrong" });
    }
};
  
export const validateotp = async (req, res) => {
    const { email, OTP } = req.body;
    try {
      const storedOtp = myCache.get(email);
  
      if (storedOtp && OTP === storedOtp) {
        myCache.del(email); 
        return res.status(200).json({ message: 'OTP verified successfully!' });
      } else {
        return res.status(401).json({ message: "OTP is not valid" });
      }
    } catch (error) {
      console.error("Error during OTP validation:", error);
      return res.status(500).json({ message: "Something went wrong" });
    }
};