const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const PostSchema = new Schema({
    user: {
        type: Schema.Types.ObjectId,
        ref: "User"
    },
    images: {
        public_id: {
            type: String,
            required: true

        },
        url: {
            type: String,
            required: true
        }
        
    },
    title: {
        type: String,
        required: true
    },
    body: {
        type: String,
        required: true
    },
    likes:{
        type: Number,
        default: 0
    },
    likedby:[{
        type: Schema.Types.ObjectId,
        ref: "User"
    }],
    comments:[{
        type: Schema.Types.ObjectId,
        ref: "Comment"
    }],
    date: {
        type: Date,
        default: Date.now
    }
});

module.exports = Post = mongoose.model("posts", PostSchema)