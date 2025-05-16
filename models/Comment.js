const mongoose = require('mongoose');

const commentSchema = new mongoose.Schema({
  team: String,
  user: String,
  text: String,
  media: String,
  profile_pic: String,
  timestamp: { type: Date, default: Date.now },
  like_reactions: { type: Number, default: 0 },
  funny_reactions: { type: Number, default: 0 },
  angry_reactions: { type: Number, default: 0 },
  love_reactions: { type: Number, default: 0 }
});

module.exports = mongoose.model('Comment', commentSchema);
