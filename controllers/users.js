import mongoose from "mongoose";
import MET from "bing-translate-api";

import Users from "../models/auth.js";


export const getAllUsers = async (req, res) => {
    const lang = req.query.language || 'en'; 
    try {
        const allUsers = await Users.find({});
        const allUserDetails = await Promise.all(allUsers.map(async user => ({
            _id: user._id,
            name: user.name,
            about: await translateText(user.about, lang),
            tags: await Promise.all(user.tags.map(tag => translateText(tag, lang))), 
            joinedOn: user.joinedOn
        })));
        res.status(200).json(allUserDetails);
    } catch (error) {
        res.status(500).json({ message: 'Failed to fetch users' });
    }
};

export const updateProfile = async (req, res) => {
    const { id: _id } = req.params;
    const { name, about, tags } = req.body;
    if (!mongoose.Types.ObjectId.isValid(_id)) {
        return res.status(404).send("User not found...");
    }
    try {
        const updatedProfile = await Users.findByIdAndUpdate(
            _id,
            { $set: { name, about, tags } },
            { new: true }
        );
        res.status(200).json(updatedProfile);
    } catch (error) {
        res.status(405).json({ message: error.message });
    }
};

async function translateText(text, lang) {  
    try {
        if (!text) {
            return "";
        }
        const translationResult = await MET.translate(text, null, lang);
        if (Array.isArray(translationResult) && translationResult.length > 0) {
            const translation = translationResult.find(trans => trans.translations.some(tr => tr.to === lang));
            if (translation) {
                const translatedText = translation.translations.find(tr => tr.to === lang).text;
                return translatedText;
            } else {
                console.error(`Translation for ${lang} not found`);
                return text; 
            }
        } else {
            console.error('Translation error: Unexpected response format');
            return text; 
        }
    } catch (error) {
        console.error('Translation error:', error);
        return text; 
    }
}

export const getLoginHistory = async (req, res) => {
    const { id: _id } = req.params; 
    if (!mongoose.Types.ObjectId.isValid(_id)) {
        return res.status(404).send("User not found...");
    }
    try {
        const user = await Users.findById(_id).select('loginHistory');
        res.status(200).json({ loginHistory: user.loginHistory });
    } catch (error) {
        res.status(500).json({ message: "Something went wrong..." });
    }
}