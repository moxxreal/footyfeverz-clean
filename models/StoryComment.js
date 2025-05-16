const mongoose = require('mongoose');

const StoryCommentSchema = new mongoose.Schema({
  story_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Story', required: true },
  username: String,
  comment: String,
  timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('StoryComment', StoryCommentSchema);
