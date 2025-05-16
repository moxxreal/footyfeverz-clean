const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const bodyParser = require('body-parser');
const fs = require('fs');
const multer = require('multer');
const dayjs = require('dayjs');
const relativeTime = require('dayjs/plugin/relativeTime');
const session = require('express-session');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const admin = require('firebase-admin');
require('dotenv').config();

dayjs.extend(relativeTime);

// --- MongoDB Connect ---
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// --- Firebase Admin ---
const decoded = Buffer.from(process.env.FIREBASE_KEY_BASE64, 'base64').toString('utf8');
admin.initializeApp({ credential: admin.credential.cert(JSON.parse(decoded)) });

// --- Models ---
const User = require('./models/user');
const Message = require('./models/Message');
const Story = require('./models/Story');
const StoryComment = require('./models/StoryComment');
const StoryReaction = require('./models/StoryReaction');
const Battle = require('./models/Battle');
const BattleVote = require('./models/BattleVote');
const Comment = require('./models/Comment');
const teamToLeagueMap = require('./teamToLeagueMap');

// --- Express Setup ---
const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));

// --- Middleware ---
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'super-secret-key',
  resave: false,
  saveUninitialized: true
}));

// --- Multer Setup ---
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/uploads/'),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${Math.random().toString(36).substring(7)}${path.extname(file.originalname)}`)
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });
const multiUpload = upload.fields([{ name: 'media', maxCount: 1 }, { name: 'profile_pic', maxCount: 1 }]);

// --- User Session Middleware ---
app.use(async (req, res, next) => {
  if (req.session.user) {
    const unreadCount = await Message.countDocuments({ receiver: req.session.user.username, seenByReceiver: false }).catch(() => 0);
    req.session.user.unreadCount = unreadCount;
  }
  res.locals.user = req.session.user;
  res.locals.request = req;
  next();
});
// --- Home Page ---
app.get('/', async (req, res) => {
  const cutoff = dayjs().subtract(24, 'hour').toDate();

  try {
    const topFans = await Comment.aggregate([
      { $group: { _id: "$user", comments: { $sum: 1 }, likes: { $sum: "$like_reactions" } } },
      { $sort: { likes: -1 } },
      { $limit: 5 },
      { $project: { _id: 0, username: "$_id", comments: 1, likes: 1 } }
    ]);

    const stories = await Story.find({ createdAt: { $gte: cutoff } }).sort({ createdAt: -1 }).lean();
    const storyIds = stories.map(s => s._id);

    const [comments, reactions] = await Promise.all([
      StoryComment.find({ story_id: { $in: storyIds } }).lean(),
      StoryReaction.aggregate([
        { $match: { story_id: { $in: storyIds } } },
        { $group: { _id: { story_id: "$story_id", reaction_type: "$reaction_type" }, count: { $sum: 1 } } }
      ])
    ]);

    const enrichedStories = stories.map(story => ({
      ...story,
      relativeTime: dayjs(story.createdAt).fromNow(),
      comments: comments.filter(c => c.story_id.toString() === story._id.toString()),
      reactions: reactions.filter(r => r._id.story_id.toString() === story._id.toString()).map(r => ({ type: r._id.reaction_type, count: r.count }))
    }));

    const battle = await Battle.findOne().sort({ created_at: -1 });

    res.render('index', { stories: enrichedStories, topFans, battle });
  } catch (err) {
    console.error('❌ Home load error:', err);
    res.status(500).send("Failed to load homepage");
  }
});

// --- Stories Upload ---
app.post('/stories/upload', upload.single('storyMedia'), async (req, res) => {
  console.log('✅ /stories/upload route hit');

  if (!req.session.user) {
    console.warn('❌ User not logged in');
    return res.redirect('/?error=Login required');
  }

  console.log('✅ Session User:', req.session.user);

  if (!req.file) {
    console.warn('❌ No file received');
    return res.redirect('/?error=No file uploaded');
  }

  console.log('✅ File Received:', req.file);

  const filePath = `/uploads/${req.file.filename}`;
  const username = req.session.user.username;
  const caption = req.body.caption || '';

  try {
    const newStory = await Story.create({
      image: filePath,
      username,
      caption,
      createdAt: new Date()
    });

    console.log('✅ Story saved to DB:', newStory);
    res.redirect('/');
  } catch (err) {
    console.error('❌ Error saving story:', err);
    res.redirect('/?error=Failed to save story');
  }
});

// --- Story React ---
app.post('/stories/:id/react', async (req, res) => {
  const { id } = req.params;
  const { reaction_type } = req.body;
  const username = req.session.user?.username;

  if (!username || !reaction_type) return res.status(400).send("Login or reaction missing");

  try {
    await StoryReaction.updateOne({ story_id: id, username, reaction_type }, { $set: { story_id: id, username, reaction_type } }, { upsert: true });
    res.json({ success: true });
  } catch (err) {
    console.error('Story react error:', err);
    res.status(500).send("Failed to react");
  }
});

// --- Story Comment ---
app.post('/stories/:id/comment', async (req, res) => {
  const { id } = req.params;
  const { comment } = req.body;
  const username = req.session.user?.username;

  if (!username || !comment?.trim()) return res.status(400).send("Login or comment missing");

  try {
    await StoryComment.create({ story_id: id, username, comment: comment.trim() });
    res.redirect('/');
  } catch (err) {
    console.error('Story comment error:', err);
    res.status(500).send("Failed to comment");
  }
});

// --- Team Comment ---
app.post('/team/:teamname/comment', multiUpload, async (req, res) => {
  if (!req.session.user) return res.status(401).send("Login required");

  const { teamname } = req.params;
  const { text } = req.body;
  const media = req.files?.media ? `/uploads/${req.files.media[0].filename}` : '';
  const profilePic = req.files?.profile_pic ? `/uploads/${req.files.profile_pic[0].filename}` : '';

  if (!text?.trim()) return res.status(400).send("Empty comment");

  try {
    await Comment.create({ team: teamname, user: req.session.user.username, text, media, profile_pic: profilePic });
    res.redirect(`/team/${teamname}`);
  } catch (err) {
    console.error('Team comment error:', err);
    res.status(500).send("Failed to post comment");
  }
});

// --- Team Page ---
app.get('/team/:teamname', async (req, res) => {
  const { teamname } = req.params;
  const sort = req.query.sort === 'top' ? { like_reactions: -1 } : { timestamp: -1 };

  try {
    const comments = await Comment.find({ team: teamname }).sort(sort);
    const leagueInfo = teamToLeagueMap[teamname] || {};
    res.render('team', { teamname, comments, sort: req.query.sort, useTeamHeader: true, leagueSlug: leagueInfo.slug || '', leagueName: leagueInfo.name || '' });
  } catch (err) {
    console.error('Team page error:', err);
    res.status(500).send("Failed to load team page");
  }
});

// --- Comment React ---
app.post('/comment/:id/react/:type', async (req, res) => {
  const { id, type } = req.params;
  const validTypes = ['like', 'funny', 'angry', 'love'];

  if (!validTypes.includes(type)) return res.status(400).json({ success: false, message: 'Invalid reaction' });

  try {
    await Comment.updateOne({ _id: id }, { $inc: { [`${type}_reactions`]: 1 } });
    res.json({ success: true });
  } catch (err) {
    console.error('React error:', err);
    res.status(500).json({ success: false });
  }
});

// --- Battle Vote ---
app.post('/battle/vote', async (req, res) => {
  const { battleId, vote } = req.body;
  const username = req.session.user?.username;

  if (!username || !vote) return res.status(400).json({ success: false, message: 'Missing data' });

  try {
    const alreadyVoted = await BattleVote.findOne({ battle_id: battleId, username });
    if (alreadyVoted) return res.json({ success: false, message: 'Already voted' });

    await BattleVote.create({ battle_id: battleId, username, voted_for: vote });
    await Battle.updateOne({ _id: battleId }, { $inc: { [vote === 'team1' ? 'votes_team1' : 'votes_team2']: 1 } });

    res.json({ success: true });
  } catch (err) {
    console.error('Vote error:', err);
    res.status(500).json({ success: false, message: 'Vote failed' });
  }
});
// --- League Pages ---
const leagues = ['laliga', 'premier', 'serie-a', 'bundesliga', 'roshn-saudi', 'eredivisie', 'liga-portugal', 'super-lig', 'ligue1'];
leagues.forEach(league => {
  app.get(`/${league}.html`, (req, res) => res.render(league));
});

// --- Tournament Pages ---
const tournaments = ['champions', 'world_cup', 'euros', 'copa_america'];
const aliases = { 'world-cup': 'world_cup', 'copa-america': 'copa_america' };

Object.entries(aliases).forEach(([dashed, underscored]) => {
  app.get(`/${dashed}.html`, (req, res) => res.redirect(`/${underscored}.html`));
});

tournaments.forEach(tournament => {
  app.get(`/${tournament}.html`, async (req, res) => {
    const sort = req.query.sort === 'top' ? { like_reactions: -1 } : { timestamp: -1 };

    try {
      const comments = await Comment.find({ team: tournament }).sort(sort);
      res.render('team', {
        teamname: tournament,
        comments,
        sort: req.query.sort,
        useTeamHeader: false,
        leagueSlug: tournament,
        leagueName: tournament.replace('_', ' ').toUpperCase()
      });
    } catch (err) {
      console.error('Tournament page error:', err);
      res.status(500).send("Failed to load tournament page");
    }
  });
});

// --- User Profile ---
app.get('/user/:username', async (req, res) => {
  const { username } = req.params;

  try {
    const comments = await Comment.find({ user: username }).sort({ timestamp: -1 }).lean();
    const totalComments = comments.length;
    const totalLikes = comments.reduce((sum, c) => sum + (c.like_reactions || 0), 0);

    const enrichedComments = comments.map(c => ({ ...c, relativeTime: dayjs(c.timestamp).fromNow() }));

    res.render('user', {
      profileUser: username,
      comments: enrichedComments,
      totalComments,
      totalLikes
    });
  } catch (err) {
    console.error('User profile error:', err);
    res.status(500).send("Failed to load profile");
  }
});

app.get('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/?error=Login required');
  res.redirect(`/user/${req.session.user.username}`);
});

// --- Inbox ---
app.get('/inbox', async (req, res) => {
  if (!req.session.user) return res.redirect('/?error=Login required');
  const username = req.session.user.username;

  try {
    const messages = await Message.find({ $or: [{ sender: username }, { receiver: username }] }).sort({ timestamp: -1 });

    const conversations = {};
    messages.forEach(msg => {
      const otherUser = msg.sender === username ? msg.receiver : msg.sender;
      if (!conversations[otherUser]) {
        conversations[otherUser] = {
          user: otherUser,
          lastMessage: msg.content,
          timestamp: msg.timestamp
        };
      }
    });

    res.render('inbox', { conversations: Object.values(conversations), currentUser: req.session.user });
  } catch (err) {
    console.error('Inbox error:', err);
    res.status(500).send("Inbox error");
  }
});

// --- Chat Page ---
app.get('/chat/:username', async (req, res) => {
  if (!req.session.user) return res.redirect('/?error=Login required');
  const { username: receiver } = req.params;
  const sender = req.session.user.username;

  if (sender === receiver) return res.redirect('/?error=Cannot chat with yourself');

  try {
    const receiverUser = await User.findOne({ username: receiver });
    if (!receiverUser) return res.status(404).send("User not found");

    await Message.updateMany({ sender: receiver, receiver: sender, seenByReceiver: false }, { $set: { seenByReceiver: true } });

    res.render('chat', { receiver: receiverUser, currentUser: req.session.user });
  } catch (err) {
    console.error('Chat load error:', err);
    res.status(500).send("Failed to load chat");
  }
});

// --- Messaging API Auth ---
app.use('/api/messages', (req, res, next) => {
  if (req.session.user) {
    req.user = { _id: req.session.user.username };
    next();
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
}, require('./routes/messages'));

// --- FCM Routes ---
app.use('/api/fcm', require('./routes/fcm'));

// --- Socket.IO ---
const connectedUsers = new Map();
const lastSeenMap = new Map();

io.on('connection', (socket) => {
  console.log('🔌 Connected:', socket.id);

  socket.on('joinRoom', ({ sender, receiver }) => {
    const room = [sender, receiver].sort().join('-');
    socket.join(room);
    connectedUsers.set(sender, socket.id);
    socket.broadcast.emit('userOnline', { username: sender });
  });

  socket.on('chatMessage', async ({ sender, receiver, content }) => {
    if (!content?.trim()) return;
    const newMsg = await Message.create({ sender, receiver, content });
    io.to([sender, receiver].sort().join('-')).emit('newMessage', newMsg);
  });

  socket.on('typing', ({ to, from }) => {
    const room = [to, from].sort().join('-');
    socket.to(room).emit('typing', { from });
  });

  socket.on('stopTyping', ({ to, from }) => {
    const room = [to, from].sort().join('-');
    socket.to(room).emit('stopTyping', { from });
  });

  socket.on('disconnect', () => {
    for (const [username, id] of connectedUsers.entries()) {
      if (id === socket.id) {
        connectedUsers.delete(username);
        const lastSeen = new Date().toISOString();
        lastSeenMap.set(username, lastSeen);
        socket.broadcast.emit('userOffline', { username, lastSeen });
        break;
      }
    }
    console.log('❌ Disconnected:', socket.id);
  });
});

// --- Background Cleanup (Stories older than 24h) ---
setInterval(async () => {
  const cutoff = dayjs().subtract(24, 'hour').toDate();
  const oldStories = await Story.find({ createdAt: { $lt: cutoff } });

  for (const story of oldStories) {
    const filePath = path.join(__dirname, 'public', story.image);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    await Promise.all([
      Story.deleteOne({ _id: story._id }),
      StoryComment.deleteMany({ story_id: story._id }),
      StoryReaction.deleteMany({ story_id: story._id })
    ]);
  }

  if (oldStories.length) console.log(`🗑️ Cleaned ${oldStories.length} old stories`);
}, 60 * 60 * 1000);
