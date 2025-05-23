const mongoose = require("mongoose");

const lostItemSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }, 
  title: { type: String, required: true },
  category: { type: String, required: true },
  subCategory: { type: String, required: true },
  brand: { type: String },
  description: { type: String },
  city: { type: String, required: true },
  location: { type: String, required: true }, 
  dateLost: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now },
  request: { type: String, default: "disapproved"},
  imageUrl: [{ type: String }],
  status: { type: String, default: "pending" }
});

module.exports = mongoose.model("LostItems", lostItemSchema);
