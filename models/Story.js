const mongoose = require('mongoose');

const StorySchema = new mongoose.Schema({
  image: { type: String, required: true },
  username: String,
  caption: String,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Story', StorySchema);
