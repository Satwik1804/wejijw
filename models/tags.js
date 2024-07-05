import mongoose from "mongoose";

const tagsSchema = mongoose.Schema({
    tagName:{
        type: String,
        required: true
    }
})

export default mongoose.model("Tag", tagsSchema)