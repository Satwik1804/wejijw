import mongoose from "mongoose";

import Questions from "../models/Questions.js";

export const postAnswer = async (req, res) => {
    const { id: _id } = req.params;
    const { answerBody, userAnswered, userId } = req.body;
    if (!mongoose.Types.ObjectId.isValid(_id)) {
        return res.status(404).send('Question not found...');
    }
    try {
        const newAnswerId = new mongoose.Types.ObjectId();
        const updatedQuestion = await Questions.findByIdAndUpdate(
            _id,
            {
                $push: {
                    answer: {
                        _id: newAnswerId,
                        answerBody,
                        userAnswered,
                        userId,
                        answeredOn: new Date()
                    }
                },
                $inc: { noOfAnswers: 1 } 
            },
            { new: true }
        );
        res.status(200).json(updatedQuestion);
    } catch (error) {
        res.status(400).json({ message: 'Error posting answer' });
    }
};

const updateNoOfQuestions = async (_id, noOfAnswers) => {
    try {
        await Questions.findByIdAndUpdate(_id, { $set: { 'noOfAnswers': noOfAnswers } });
    } catch (error) {
        console.log(error);
    }
};

export const deleteAnswer = async (req, res) => {
    const { id: _id } = req.params;
    const { answerId, noOfAnswers } = req.body;
    if (!mongoose.Types.ObjectId.isValid(_id)) {
        return res.status(404).send("question unavailable...");
    }
    if (!mongoose.Types.ObjectId.isValid(answerId)) {
        return res.status(404).send("answer unavailable...");
    }
    if (typeof noOfAnswers !== 'number' || noOfAnswers < 0) {
        return res.status(400).send("Invalid number of answers...");
    }
    updateNoOfQuestions(_id, noOfAnswers);
    try {
        await Questions.updateOne(
            { _id },
            { $pull: { answer: { _id: answerId } } }
        );
        res.status(200).json({ message: "successfully deleted.." });
    } catch (error) {
        res.status(404).json({ message: "error in deleting.." });
    }
};