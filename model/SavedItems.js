const mongoose = require("mongoose");
const savedItemsSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }, 
    itemId: { type: mongoose.Schema.Types.ObjectId, ref: "LostItems", required: true }, 
    isSaved: { type: Boolean, default: false},
    isDeleted: { type: Boolean, default: false},
    SavedAt: { type: Date},
})

module.exports = mongoose.model("SavedItems", savedItemsSchema);