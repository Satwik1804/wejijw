import mongoose from "mongoose";
import MET from "bing-translate-api";

import Questions from "../models/Questions.js"


export const AskQuestion = async (req, res) => {
    const postQuestionData = req.body;
    const postQuestion = new Questions(postQuestionData)       
    try{
        await postQuestion.save();
        res.status(200).json("Posted a question successfully")
    } catch(error) {
        console.log(error)
        res.status(409).json("Couldn't post a new question")
    }
}

export const getAllQuestions = async (req, res) => {
  let lang = req.query.language;
  if (lang === 'zh') {
    lang = 'zh-Hans';
  }

  try {
    const questionList = await Questions.find().populate('answer', '_id answerBody userAnswered userId answeredOn').exec();

    const questionListData = await Promise.all(questionList.map(async question => ({
      _id: question._id,
      questionTitle: await translateText(question.questionTitle || '', lang),
      questionBody: await translateText(question.questionBody || '', lang),
      questionTags: await Promise.all((question.questionTags || []).map(tag => translateText(tag, lang))),
      noOfAnswers: question.noOfAnswers || 0,
      upVote: question.upVote || [],
      downVote: question.downVote || [],
      userPosted: question.userPosted || '',
      userId: question.userId || '',
      askedOn: question.askedOn || '',
      answer: await Promise.all((question.answer || []).map(async ans => ({
        _id: ans._id, 
        answerBody: await translateText(ans.answerBody || '', lang),
        userAnswered: ans.userAnswered || '',
        userId: ans.userId || '',
        answeredOn: ans.answeredOn || ''
      })))
    })));

    res.status(200).json(questionListData);
  } catch (error) {
    console.error('Error fetching questions:', error.message);
    res.status(404).json({ message: error.message });
  }
};

export const deleteQuestion = async (req, res) => {
    const { id:_id } = req.params
    if(!mongoose.Types.ObjectId.isValid( _id )){
        return res.status(404).send('question unavailable...');
    }
    try {
        await Questions.findByIdAndDelete( _id )
        res.status(200).json({ message: "successfully deleted..." })
    } catch (error) {
        res.status(404).json({ message: error.message })
    }
}

export const voteQuestion = async (req, res) => {
    const { id: _id } = req.params;
    const { value, userId } = req.body;
  
    if (!mongoose.Types.ObjectId.isValid(_id)) {
      return res.status(404).send("question unavailable...");
    }
  
    try {
      const question = await Questions.findById(_id);
      const upIndex = question.upVote.findIndex((id) => id === String(userId));
      const downIndex = question.downVote.findIndex(
        (id) => id === String(userId)
      );
  
      if (value === "upVote") {
        if (downIndex !== -1) {
          question.downVote = question.downVote.filter(
            (id) => id !== String(userId)
          );
        }
        if (upIndex === -1) {
          question.upVote.push(userId);
        } else {
          question.upVote = question.upVote.filter((id) => id !== String(userId));
        }
      } else if (value === "downVote") {
        if (upIndex !== -1) {
          question.upVote = question.upVote.filter((id) => id !== String(userId));
        }
        if (downIndex === -1) {
          question.downVote.push(userId);
        } else {
          question.downVote = question.downVote.filter(
            (id) => id !== String(userId)
          );
        }
      }
      await Questions.findByIdAndUpdate(_id, question);
      res.status(200).json({ message: "voted successfully..." });
    } catch (error) {
      res.status(404).json({ message: "id not found" });
    }
};

async function translateText(text, lang) {  
  try {
      const translatedText = await MET.translate(text, null, lang);
      return translatedText.translation
  } catch (error) {
      console.error('Translation error:', error);
      return text;
  }
}