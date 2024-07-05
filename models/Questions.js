import mongoose from 'mongoose';

const AnswerSchema = new mongoose.Schema({
    _id: mongoose.Schema.Types.ObjectId,
    answerBody: {
        type: String,
        required: true
    },
    userAnswered: {
        type: String,
        required: true
    },
    userId: {
        type: String,
        required: true
    },
    answeredOn: {
        type: Date,
        default: Date.now
    }
});

const QuestionSchema = new mongoose.Schema({
    questionTitle: {
        type: String,
        required: true
    },
    questionBody: {
        type: String,
        required: true
    },
    questionTags: {
        type: [String],
        required: true
    },
    noOfAnswers: {
        type: Number,
        default: 0
    },
    upVote: {
        type: [String],
        default: []
    },
    downVote: {
        type: [String],
        default: []
    },
    userPosted: {
        type: String,
        required: true
    },
    userId: {
        type: String,
        required: true
    },
    askedOn: {
        type: Date,
        default: Date.now
    },
    answer: [AnswerSchema] 
});

const Question = mongoose.model('Question', QuestionSchema);

export default Question;