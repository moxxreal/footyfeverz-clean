const mongoose = require('mongoose');

const battleSchema = new mongoose.Schema({
  team1: String,
  team2: String,
  votes_team1: { type: Number, default: 0 },
  votes_team2: { type: Number, default: 0 },
  created_at: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Battle', battleSchema);
