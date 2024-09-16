const mongoose = require('mongoose');
const Schema=mongoose.Schema;


const UserSchema=new Schema({
    fullname:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true
    },
    password:{
        type:String,
        required:true
    },
    profilepic:{

        public_id: {
            type: String,
            required: true

        },
        url: {
            type: String,
            required: true
        }
    },

    
    friends:[{type:Schema.Types.ObjectId,ref:'User'}],
    friendrequests:[{type:Schema.Types.ObjectId,ref:'User'}],
    posts:[{type:Schema.Types.ObjectId,ref:'Post'}],
    comments:[{type:Schema.Types.ObjectId,ref:'Comment'}],
    notifications:[{type:Schema.Types.ObjectId,ref:'Notification'}],
    status:{
        type:String,
        enum:['online','offline','invisible'],
        default:'offline'
    },
    lastActive:{
        type:Date,
        default:Date.now
    },
    createdAt:{
        type:Date,
        default:Date.now
    }

});

module.exports=mongoose.model('User',UserSchema);

