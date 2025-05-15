const express = require('express');
const router = express.Router();
const Message = require('../models/Message');

// Send a message
router.post('/send', async (req, res) => {
  const { receiver, content } = req.body; // ✅ receiver, not receiverId
  const sender = req.user && req.user._id;

  if (!sender || !receiver || !content?.trim()) {
    return res.status(400).json({ error: 'Missing sender, receiver, or message content.' });
  }

  try {
    const message = new Message({
      sender,
      receiver,
      content: content.trim()
    });

    await message.save();
    res.status(201).json({ message: 'Message sent', data: message });
  } catch (err) {
    console.error('Send error:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Get conversation between two users
router.get('/conversation/:userId', async (req, res) => {
  const user1 = req.user.username;
  const user2 = req.params.userId;

  try {
    // Mark messages sent to the current user as seen
    await Message.updateMany(
      { sender: user2, receiver: user1, seenByReceiver: false },
      { $set: { seenByReceiver: true } }
    );

    const messages = await Message.find({
      $or: [
        { sender: user1, receiver: user2 },
        { sender: user2, receiver: user1 }
      ]
    }).sort({ timestamp: 1 });

    res.status(200).json(messages);
  } catch (err) {
    console.error('Conversation error:', err);
    res.status(500).json({ error: 'Could not fetch messages' });
  }
});
module.exports = router;
