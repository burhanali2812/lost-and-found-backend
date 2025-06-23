const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true , sparse: true},
    password: { type: String, required: true ,  default: null},
    phone: { type: String, required: true },
    cnic: { type: String, required: true, unique: true , sparse: true},
    address: { type: String, required: true },
    isVerified: { type: String, required: true, default: "requested" },
    profileImage : { type: String, required: true ,  default: null},
    frontCnic : { type: String, required: true ,  default: null},
    backCnic : { type: String, required: true ,  default: null},
    role: { type: String, required: true, default: "user" },
    createdAt: { type: Date, default: Date.now }
  });
  
  module.exports = mongoose.model("User", userSchema);