const mongoose = require("mongoose");
const savedItemsSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }, 
    itemId: { type: mongoose.Schema.Types.ObjectId, ref: "LostItems", required: true }, 
    isSaved: { type: Boolean, default: false},
    isDeleted: { type: Boolean, default: false},
    isDeletedFromDisplayed: { type: Boolean, default: false},
    createdAt: { type: Date, default: Date.now },
    SavedAt: { type: Date},
})

module.exports = mongoose.model("SavedItems", savedItemsSchema);