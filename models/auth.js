import mongoose from "mongoose";

const userSchema = mongoose.Schema({
    name:{
        type: String,
        required: true
    },
    email:{
        type: String,
        required: true
    },
    phoneNumber:{
        type: String,
        required: true
    },
    password:{
        type: String,
        required: true
    },
    about:{
        type: String
    },
    tags:{
        type: [String]
    },
    joinedOn:{
        type: Date,
        default: Date.now
    },
    otp:{
        type: String,
        default: ""
    },
    otpExpires:{
        type: Date,
        default: Date.now
    },
    lang:{
        type: String,
        default: "en"
    },
    loginHistory: [{
        loginTime: {
            type: Date,
            default: Date.now
        },
        ipAddress: {
            type: String
        },
        browser: {
            type: String
        },
        os: {
            type: String
        },
        device: {
            type: String
        }
    }]
})

export default mongoose.model("User", userSchema)