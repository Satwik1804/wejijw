import mongoose from "mongoose";

const tagsListSchema = mongoose.Schema({
    tagName:{
        type: String,
        required: true
    },
    tagDesc:{
        type: String,
        required: true
    }
})

export default mongoose.model("TagsList", tagsListSchema)