const mongoose = require('mongoose');

const messageSchema = new mongoose.Schema({
  sender: { type: String, required: true },     // username
  receiver: { type: String, required: true },   // username
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  seenByReceiver: { type: Boolean, default: false }
});

module.exports = mongoose.model('Message', messageSchema);
