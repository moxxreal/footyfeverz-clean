const mongoose = require('mongoose');

const battleVoteSchema = new mongoose.Schema({
  battleId: { type: mongoose.Schema.Types.ObjectId, ref: 'Battle', required: true },
  username: { type: String, required: true },
  votedFor: { type: String, enum: ['team1', 'team2'], required: true }
}, { timestamps: true });

battleVoteSchema.index({ battleId: 1, username: 1 }, { unique: true });

module.exports = mongoose.model('BattleVote', battleVoteSchema);
