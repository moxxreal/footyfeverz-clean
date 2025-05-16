const mongoose = require('mongoose');

const StoryReactionSchema = new mongoose.Schema({
  story_id: { type: mongoose.Schema.Types.ObjectId, ref: 'Story', required: true },
  username: String,
  reaction_type: String
}, { timestamps: true });

StoryReactionSchema.index({ story_id: 1, username: 1, reaction_type: 1 }, { unique: true });

module.exports = mongoose.model('StoryReaction', StoryReactionSchema);
