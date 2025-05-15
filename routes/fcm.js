// routes/fcm.js
const express = require('express');
const router = express.Router();
const User = require('../models/User'); // Adjust path if needed

router.post('/save-token', async (req, res) => {
  const { username, token } = req.body;
  if (!username || !token) return res.status(400).json({ error: 'Missing data' });

  try {
    await User.updateOne(
      { username },
      { $set: { fcmToken: token } },
      { upsert: true }
    );
    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Failed to save FCM token:', err);
    res.status(500).json({ error: 'Failed to save token' });
  }
});

module.exports = router;
