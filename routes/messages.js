const express = require('express');
const router = express.Router();
const Message = require('../models/Message');

// --- Send a Message ---
router.post('/send', async (req, res) => {
  const sender = req.user?._id;
  const { receiver, content } = req.body;

  if (!sender || !receiver || !content?.trim()) {
    return res.status(400).json({ error: 'Missing sender, receiver, or message content.' });
  }

  try {
    const message = await Message.create({ sender, receiver, content: content.trim() });
    res.status(201).json({ message: 'Message sent', data: message });
  } catch (err) {
    console.error('Send error:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// --- Get Conversation Between Users ---
router.get('/conversation/:userId', async (req, res) => {
  const currentUser = req.user?._id;
  const otherUser = req.params.userId;

  if (!currentUser || !otherUser) {
    return res.status(400).json({ error: 'Missing user data' });
  }

  try {
    // Mark incoming messages as seen
    await Message.updateMany(
      { sender: otherUser, receiver: currentUser, seenByReceiver: false },
      { $set: { seenByReceiver: true } }
    );

    const messages = await Message.find({
      $or: [
        { sender: currentUser, receiver: otherUser },
        { sender: otherUser, receiver: currentUser }
      ]
    }).sort({ timestamp: 1 });

    res.json(messages);
  } catch (err) {
    console.error('Conversation error:', err);
    res.status(500).json({ error: 'Failed to load conversation' });
  }
});

module.exports = router;
