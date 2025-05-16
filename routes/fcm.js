const express = require('express');
const router = express.Router();
const User = require('../models/user');

// Save FCM Token
router.post('/save-token', async (req, res) => {
  const { username, token } = req.body;

  if (!username || !token) return res.status(400).json({ error: 'Missing username or token' });

  try {
    await User.updateOne({ username }, { $set: { fcmToken: token } }, { upsert: true });
    res.json({ success: true });
  } catch (err) {
    console.error('Failed to save FCM token:', err);
    res.status(500).json({ error: 'Failed to save token' });
  }
});

module.exports = router;
