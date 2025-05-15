// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: String,
  password: String // optional if used only for reference
});

module.exports = mongoose.model('User', userSchema);
