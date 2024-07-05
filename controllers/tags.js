import MET from "bing-translate-api"

import TagsList from "../models/tagsList.js";
import Tags from "../models/tags.js";


export const getTagsList = async (req, res) => {
    var lang = req.query.language || 'en';
    if(lang=="zh") {
        lang = "zh-Hans"
    }
    try {
        const allTags = await TagsList.find({});
        const TagsListDetails = await Promise.all(allTags.map(async tag => ({
            _id: tag._id,
            tagName: await translateText(tag.tagName, lang),
            tagDesc: await translateText(tag.tagDesc, lang),
        })));
        res.status(200).json(TagsListDetails);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

export const getAllTags = async (req, res) => {
    var lang = req.query.language || 'en';
    if(lang=="zh") {
        lang = "zh-Hans"
    }
    try {
        const allTags = await Tags.find({});
        const TagsDetails = await Promise.all(allTags.map(async tag => ({
            _id: tag._id,
            tagName: await translateText(tag.tagName, lang)
        })));
        res.status(200).json(TagsDetails);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
}

async function translateText(text, lang) {  
    try {
        const translatedText = await MET.translate(text, null, lang);
        return translatedText.translation
    } catch (error) {
        console.error('Translation error:', error);
        return text;
    }
}