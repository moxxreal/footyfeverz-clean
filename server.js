const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const bodyParser = require('body-parser');
const fs = require('fs');
const multer = require('multer');
const dayjs = require('dayjs');
const relativeTime = require('dayjs/plugin/relativeTime');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const webpush = require('web-push');

// Setup Express and middleware
const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

// Extend dayjs
dayjs.extend(relativeTime);

// Firebase Admin
const admin = require('firebase-admin');

const serviceAccount = JSON.parse(
  Buffer.from(process.env.FIREBASE_KEY_BASE64, 'base64').toString('utf8')
);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// --- Models & Middleware ---
const Message = require('./models/Message');
const User = require('./models/user');
const messageRoutes = require('./routes/messages');
const fcmRoutes = require('./routes/fcm');
const isAuthenticated = require('./middleware/isAuthenticated');
const teamToLeagueMap = require('./teamToLeagueMap');

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/uploads/'),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + ext;
    cb(null, uniqueName);
  }
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });
const multiUpload = upload.fields([
  { name: 'media', maxCount: 1 },
  { name: 'profile_pic', maxCount: 1 }
]);
// App middleware
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'your-secret-key5ff583e7330e6d76299bedf5cda9ffd6d91ecb1d56bdf459d4e32b5944cfb3a8fb9b114f88f7cf484f2bad68b91eff813f8898e76dde4a8057b14325f5365b95',
  resave: false,
  saveUninitialized: true
}));

// --- Route Fix ---
app.post('/team/:teamname/comment', multiUpload, (req, res) => {
  if (!req.session || !req.session.user) {
    return res.status(401).send("You must be logged in to comment.");
  }

  const { teamname } = req.params;
  const text = req.body.text?.trim();
  const user = req.session.user.username;
  const timestamp = new Date().toISOString();

  if (!text) return res.status(400).send("Comment text cannot be empty.");

  const mediaPath = req.files?.media ? `/uploads/${req.files.media[0].filename}` : '';
  const profilePicPath = req.files?.profile_pic ? `/uploads/${req.files.profile_pic[0].filename}` : '';

  db.run(
    "INSERT INTO comments (team, user, text, media, profile_pic, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
    [teamname, user, text, mediaPath, profilePicPath, timestamp],
    err => {
      if (err) return res.status(500).send("Failed to post comment");
      res.redirect(`/team/${teamname}`);
    }
  );
});

// --- Setup socket events ---
const connectedUsers = new Map();
const lastSeenMap = new Map();

io.on('connection', (socket) => {
  console.log('New user connected:', socket.id);

  socket.on('joinRoom', ({ sender, receiver }) => {
    const room = [sender, receiver].sort().join('-');
    socket.join(room);
    connectedUsers.set(sender, socket.id);
    socket.broadcast.emit('userOnline', { username: sender });
  });

  socket.on('chatMessage', async ({ sender, receiver, content }) => {
    if (!content?.trim()) return;
    console.log('✅ [server] chatMessage received:', sender, '→', receiver, content);

    const newMsg = new Message({ sender, receiver, content });
    await newMsg.save();

    const room = [sender, receiver].sort().join('-');
    io.to(room).emit('newMessage', newMsg);

    try {
      const receiverUser = await User.findOne({ username: receiver });
      if (receiverUser && receiverUser.fcmToken) {
        const payload = {
          notification: {
            title: `New message from ${sender}`,
            body: content,
            icon: '/images/favicon.png'
          },
          token: receiverUser.fcmToken
        };

        admin.messaging().send(payload)
          .then(response => console.log('Push notification sent:', response))
          .catch(err => console.error('Push notification error:', err));
      }
    } catch (err) {
      console.error('Failed to fetch user or send push:', err);
    }
  });

  socket.on('typing', ({ to, from }) => {
    const room = [to, from].sort().join('-');
    socket.to(room).emit('typing', { from });
  });

  socket.on('stopTyping', ({ to, from }) => {
    const room = [to, from].sort().join('-');
    socket.to(room).emit('stopTyping', { from });
  });

  socket.on('checkOnlineStatus', ({ userToCheck }) => {
    if (connectedUsers.has(userToCheck)) {
      socket.emit('userOnline', { username: userToCheck });
    } else {
      const lastSeen = lastSeenMap.get(userToCheck);
      socket.emit('userOffline', { username: userToCheck, lastSeen });
    }
  });

  socket.on('disconnect', () => {
    for (const [username, id] of connectedUsers.entries()) {
      if (id === socket.id) {
        connectedUsers.delete(username);
        const now = new Date().toISOString();
        lastSeenMap.set(username, now);
        socket.broadcast.emit('userOffline', { username, lastSeen: now });
        break;
      }
    }
    console.log('User disconnected:', socket.id);
  });
});

// MongoDB connect
mongoose.connect('mongodb://localhost:27017/footyforum')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB error:', err));

// SQLite DB setup
const db = new sqlite3.Database('./forum.db', err => {
  if (err) console.error("Database error:", err);
  else console.log("Connected to SQLite database");
});

// --- User Session Handling ---
app.use(async (req, res, next) => {
  if (req.session.user) {
    const unreadCount = await Message.countDocuments({
      receiver: req.session.user.username,
      seenByReceiver: false
    }).catch(() => 0);
    req.session.user.unreadCount = unreadCount;
  }
  res.locals.user = req.session.user;
  res.locals.request = req;
  next();
});
// --- Messaging API ---
app.use('/api/messages', (req, res, next) => {
  if (req.session.user) {
    req.user = { _id: req.session.user.username };
    next();
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
}, messageRoutes);

app.use('/api/fcm', fcmRoutes);
// --- Chat Page ---
app.get('/chat', (req, res) => {
  return res.redirect('/?error=No%20user%20selected%20for%20chat');
});
app.get('/chat/:username', async (req, res) => {
  if (!req.session.user) {
    return res.redirect('/?error=You must be logged in to chat');
  }
  const currentUsername = req.session.user.username;
  const receiverUsername = req.params.username;

  if (currentUsername === receiverUsername) {
    return res.redirect('/?error=Cannot%20chat%20with%20yourself');
  }

  db.get("SELECT * FROM users WHERE username = ?", [receiverUsername], async (err, receiver) => {
    if (err || !receiver) {
      console.error('User not found:', err);
      return res.status(404).send("User not found");
    }

    try {
      await Message.updateMany(
        { sender: receiverUsername, receiver: currentUsername, seenByReceiver: false },
        { $set: { seenByReceiver: true } }
      );
    } catch (updateErr) {
      console.error('Failed to mark messages as seen:', updateErr);
    }

    res.render('chat', {
      receiver,
      currentUser: req.session.user
    });
  });
});

// --- Inbox Page ---
app.get('/inbox', async (req, res) => {
  if (!req.session.user) return res.redirect('/?error=Login required');
  const username = req.session.user.username;

  try {
    const messages = await Message.find({
      $or: [ { sender: username }, { receiver: username } ]
    }).sort({ timestamp: -1 });

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

    res.render('inbox', {
      conversations: Object.values(conversations),
      currentUser: req.session.user
    });
  } catch (err) {
    console.error('Inbox error:', err);
    res.status(500).send("Failed to load inbox.");
  }
});

// --- Middleware to make user available in all views ---
app.use((req, res, next) => {
  res.locals.user = req.session.user;
  res.locals.request = req;
  next();
});
// --- Cleanup Stories Older Than 24 Hours ---
setInterval(() => {
  const cutoff = dayjs().subtract(24, 'hour').toISOString();
  db.all("SELECT * FROM stories WHERE createdAt < ?", [cutoff], (err, rows) => {
    if (rows) {
      rows.forEach(row => {
        const filePath = path.join(__dirname, 'public', row.image);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        db.run("DELETE FROM stories WHERE id = ?", [row.id]);
      });
    }
  });
}, 60 * 60 * 1000);

// --- Create Tables ---
const initStoryTables = () => {
  db.run(`CREATE TABLE IF NOT EXISTS stories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    image TEXT NOT NULL,
    username TEXT,
    caption TEXT,
    createdAt TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS story_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    story_id INTEGER,
    username TEXT,
    comment TEXT,
    timestamp TEXT NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS story_reactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    story_id INTEGER,
    username TEXT,
    reaction_type TEXT,
    UNIQUE(story_id, username, reaction_type)
  )`);
};
initStoryTables();

db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE,
  password TEXT NOT NULL
)`);
db.run(`CREATE TABLE IF NOT EXISTS battles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  team1 TEXT NOT NULL,
  team2 TEXT NOT NULL,
  votes_team1 INTEGER DEFAULT 0,
  votes_team2 INTEGER DEFAULT 0,
  created_at TEXT NOT NULL
)`);
db.run(`CREATE TABLE IF NOT EXISTS battle_votes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  battle_id INTEGER,
  username TEXT,
  voted_for TEXT,
  UNIQUE(battle_id, username)
)`);

// --- Insert default test battle if none exists ---
db.get("SELECT COUNT(*) AS count FROM battles", (err, row) => {
  if (!err && row.count === 0) {
    const now = new Date().toISOString();
    db.run(
      `INSERT INTO battles (team1, team2, votes_team1, votes_team2, created_at)
       VALUES (?, ?, 0, 0, ?)`,
      ['Real Madrid', 'Barcelona', now],
      (err) => {
        if (err) console.error('Failed to insert test battle:', err);
        else console.log('Inserted default battle: Real Madrid vs Barcelona');
      }
    );
  }
});

// --- Home Page with Top Fans and Fan Battle ---
app.get('/', (req, res) => {
  const cutoff = dayjs().subtract(24, 'hour').toISOString();
  db.all(`
    SELECT user AS username,
           COUNT(*) AS comments,
           SUM(COALESCE(like_reactions, 0)) AS likes
    FROM comments
    GROUP BY user
    ORDER BY likes DESC
    LIMIT 5
  `, (err, topFans) => {
    if (err) return res.status(500).send("Database error (top fans)");

    db.all("SELECT * FROM stories WHERE createdAt >= ? ORDER BY createdAt DESC", [cutoff], (err, stories) => {
      if (err) return res.status(500).send("Database error (stories)");
      stories = stories.map(s => ({ ...s, relativeTime: dayjs(s.createdAt).fromNow() }));

      db.get(`SELECT * FROM battles ORDER BY created_at DESC LIMIT 1`, (err, battle) => {
        if (err) return res.status(500).send("Database error (battle)");
        res.render('index', { stories, topFans, battle });
      });
    });
  });
});

// --- Story Upload ---
app.post('/stories/upload', (req, res, next) => {
  if (!req.session.user) {
    return res.redirect('/?error=You must be logged in to post stories.');
  }
  next();
}, upload.single('storyMedia'), (req, res) => {
  try {
    if (!req.file) return res.redirect('/?error=No file uploaded');

    const filePath = `/uploads/${req.file.filename}`;
    const createdAt = new Date().toISOString();
    const username = req.session.user.username;
    const caption = req.body.caption || '';

    db.run(
      "INSERT INTO stories (image, username, caption, createdAt) VALUES (?, ?, ?, ?)",
      [filePath, username, caption, createdAt],
      err => {
        if (err) return res.redirect('/?error=Failed to save story');
        res.redirect('/');
      }
    );
  } catch (err) {
    const message = err.code === 'LIMIT_FILE_SIZE'
      ? 'Video too large (max 50MB)'
      : 'Upload failed';
    res.redirect(`/?error=${message}`);
  }
});

// --- Delete Story ---
app.post('/stories/delete/:id', (req, res) => {
  const storyId = req.params.id;
  db.get("SELECT * FROM stories WHERE id = ?", [storyId], (err, story) => {
    if (err || !story) return res.status(404).send("Story not found");
    const imagePath = path.join(__dirname, 'public', story.image);
    if (fs.existsSync(imagePath)) fs.unlinkSync(imagePath);
    db.run("DELETE FROM stories WHERE id = ?", [storyId], err => {
      if (err) return res.status(500).send("Failed to delete story");
      res.redirect('/');
    });
  });
});

// --- Fan Battle Voting ---
app.post('/battle/vote', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ success: false, message: 'You must be logged in to vote.' });
  }

  const { battleId, vote } = req.body;
  const username = req.session.user.username;
  const field = vote === 'team1' ? 'votes_team1' : vote === 'team2' ? 'votes_team2' : null;

  if (!field) return res.status(400).json({ success: false });

  db.get("SELECT * FROM battle_votes WHERE battle_id = ? AND username = ?", [battleId, username], (err, row) => {
    if (err) return res.status(500).json({ success: false });
    if (row) return res.json({ success: false, message: 'You already voted.' });

    db.run(`INSERT INTO battle_votes (battle_id, username, voted_for) VALUES (?, ?, ?)`, [battleId, username, vote], (err) => {
      if (err) return res.status(500).json({ success: false });

      db.run(`UPDATE battles SET ${field} = ${field} + 1 WHERE id = ?`, [battleId], (err) => {
        if (err) return res.status(500).json({ success: false });
        res.json({ success: true, votedFor: vote });
      });
    });
  });
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
  app.get(`/${tournament}.html`, (req, res) => {
    const sort = req.query.sort;
    const orderBy = sort === 'top' ? 'likes DESC' : 'timestamp DESC';
    db.all("SELECT * FROM comments WHERE team = ? ORDER BY " + orderBy, [tournament], (err, comments) => {
      if (err) return res.status(500).send("Database error");
      res.render('team', {
        teamname: tournament,
        comments,
        sort,
        useTeamHeader: false,
        teamnameToLeagueSlug: tournament,
        teamnameToLeagueName: tournament.replace('_', ' ').toUpperCase()
      });
    });
  });
});

// --- Team Pages ---
app.get('/team/:teamname', (req, res) => {
  const { teamname } = req.params;
  const { sort } = req.query;
  const orderBy = sort === 'top' ? 'likes DESC' : 'timestamp DESC';
  db.all("SELECT * FROM comments WHERE team = ? ORDER BY " + orderBy, [teamname], (err, comments) => {
    if (err) return res.status(500).send("Database error");
    const leagueInfo = teamToLeagueMap[teamname] || {};
    res.render('team', {
      teamname,
      comments,
      sort,
      useTeamHeader: true,
      leagueSlug: leagueInfo.slug || '',
      leagueName: leagueInfo.name || ''
    });
  });
});

// --- React to Comments ---
app.post('/comment/:id/react/:type', (req, res) => {
  const { id, type } = req.params;
  const validTypes = { like: 'like_reactions', funny: 'funny_reactions', angry: 'angry_reactions', love: 'love_reactions' };
  const field = validTypes[type];
  if (!field) return res.status(400).json({ success: false, message: 'Invalid reaction type' });

  db.run(`UPDATE comments SET ${field} = ${field} + 1 WHERE id = ?`, [id], err => {
    if (err) return res.status(500).json({ success: false, message: 'Failed to react' });
    res.json({ success: true });
  });
});

// --- Authentication ---
app.post('/signup', (req, res) => {
  const { username, email, password, redirectTo } = req.body;
  const hashed = bcrypt.hashSync(password, 10);
  db.run("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", [username, email, hashed], function(err) {
    if (err) return res.redirect(`${redirectTo || '/'}?error=Username%20or%20email%20already%20taken`);
    req.session.user = { id: this.lastID, username };
    res.redirect(redirectTo || '/');
  });
});

app.post('/login', (req, res) => {
  const { username, password, redirectTo } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.redirect(`${redirectTo || '/'}?error=Invalid%20username%20or%20password`);
    }
    req.session.user = { id: user.id, username: user.username };
    res.redirect(redirectTo || '/');
  });
});

app.get('/logout', (req, res) => {
  const redirectTo = req.query.redirectTo || '/';
  req.session.destroy(() => res.redirect(redirectTo));
});

// --- Admin Add Battle Page ---
app.get('/admin/add-battle', (req, res) => {
  res.render('admin-add-battle');
});

app.post('/admin/add-battle', (req, res) => {
  const { team1, team2 } = req.body;
  if (!team1 || !team2) return res.send("Both team names are required.");
  const createdAt = new Date().toISOString();
  db.run(
    `INSERT INTO battles (team1, team2, created_at) VALUES (?, ?, ?)`,
    [team1, team2, createdAt],
    (err) => {
      if (err) return res.send("Failed to create battle.");
      res.redirect('/fan-battle');
    }
  );
});

// --- User Profile Page ---
app.get('/user/:username', (req, res) => {
  const { username } = req.params;
  db.all(`SELECT * FROM comments WHERE user = ? ORDER BY timestamp DESC`, [username], (err, comments) => {
    if (err) return res.status(500).send("Database error (user comments)");
    const totalComments = comments.length;
    const totalLikes = comments.reduce((sum, c) => sum + (c.like_reactions || 0), 0);
    
    // ➕ Add this line to map relative time
    const enrichedComments = comments.map(c => ({ ...c, relativeTime: dayjs(c.timestamp).fromNow() }));

    res.render('user', {
      profileUser: username,
      comments: enrichedComments,
      totalComments,
      totalLikes
    });
  });
});

app.get('/profile', (req, res) => {
  if (!req.session.user) return res.redirect('/?error=You%20must%20be%20logged%20in');
  const username = req.session.user.username;
  res.redirect(`/user/${username}`);
});

// in app.js or server.js
app.use('/api/messages', isAuthenticated, messageRoutes);
// middleware/isAuthenticated.js
module.exports = function(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Not authenticated' });
};

app.get('/inbox', async (req, res) => {
  if (!req.session.user) return res.redirect('/?error=Login%20required');

  const currentUserId = req.session.user.id;

  try {
    // Fetch all messages involving the current user
    const messages = await Message.find({
      $or: [{ sender: currentUserId }, { receiver: currentUserId }]
    }).sort({ timestamp: -1 }).populate('sender receiver');

    // Create a unique set of conversation partners
    const uniqueConversations = {};
    messages.forEach(msg => {
      const otherUser = (msg.sender.id === currentUserId) ? msg.receiver : msg.sender;
      if (!uniqueConversations[otherUser.id]) {
        uniqueConversations[otherUser.id] = {
          user: otherUser,
          lastMessage: msg.content,
          timestamp: msg.timestamp
        };
      }
    });

    const conversations = Object.values(uniqueConversations).sort((a, b) =>
      new Date(b.timestamp) - new Date(a.timestamp)
    );

    res.render('inbox', { conversations, currentUser: req.session.user });
  } catch (err) {
    console.error(err);
    res.status(500).send("Inbox error");
  }
});
io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  socket.on('chat message', (msg) => {
    io.emit('chat message', msg); // broadcast to all
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
  socket.on('typing', ({ to, from }) => {
    const room = [to, from].sort().join('-');
    socket.to(room).emit('typing', { from });
  });
  
  socket.on('stopTyping', ({ to, from }) => {
    const room = [to, from].sort().join('-');
    socket.to(room).emit('stopTyping', { from });
  });  
});
// routes/fcm.js
const router = express.Router();
router.post('/save-token', async (req, res) => {
  const { username, token } = req.body;
  if (!username || !token) return res.status(400).json({ error: 'Missing data' });

  try {
    await User.updateOne({ username }, { $set: { fcmToken: token } }, { upsert: true });
    res.status(200).json({ success: true });
  } catch (err) {
    console.error('Failed to save FCM token:', err);
    res.status(500).json({ error: 'Failed to save token' });
  }
});

module.exports = router;
// generate-vapid.js
const keys = webpush.generateVAPIDKeys();
console.log('Public VAPID Key:', keys.publicKey);
console.log('Private VAPID Key:', keys.privateKey);

app.get('/', (req, res) => {
  const cutoff = dayjs().subtract(24, 'hour').toISOString();
  
  db.all(`
    SELECT user AS username,
           COUNT(*) AS comments,
           SUM(COALESCE(like_reactions, 0)) AS likes
    FROM comments
    GROUP BY user
    ORDER BY likes DESC
    LIMIT 5
  `, (err, topFans) => {
    if (err) return res.status(500).send("Database error (top fans)");

    db.all("SELECT * FROM stories WHERE createdAt >= ? ORDER BY createdAt DESC", [cutoff], (err, stories) => {
      if (err) return res.status(500).send("Database error (stories)");

      const storyIds = stories.map(s => s.id);
      const enrichedStories = [];

      if (storyIds.length === 0) {
        return res.render('index', { stories: [], topFans, battle: null });
      }

      app.post('/stories/upload', upload.single('storyMedia'), (req, res) => {
  if (!req.file) return res.redirect('/?error=No file uploaded');
  const filePath = `/uploads/${req.file.filename}`;
  const createdAt = new Date().toISOString();
  const username = req.session.user?.username || '';
  const caption = req.body.caption || '';

  db.run("INSERT INTO stories (image, username, caption, createdAt) VALUES (?, ?, ?, ?)",
    [filePath, username, caption, createdAt],
    err => {
      if (err) return res.redirect('/?error=Failed to save story');
      res.redirect('/');
    });
});

      // Load comments and reactions
      db.all("SELECT * FROM story_comments WHERE story_id IN (" + storyIds.map(() => '?').join(',') + ")", storyIds, (err, comments) => {
        if (err) return res.status(500).send("Error loading comments");

        db.all("SELECT story_id, reaction_type, COUNT(*) as count FROM story_reactions GROUP BY story_id, reaction_type", (err, reactions) => {
          if (err) return res.status(500).send("Error loading reactions");

          stories.forEach(story => {
            const storyComments = comments.filter(c => c.story_id === story.id);
            const storyReactions = reactions.filter(r => r.story_id === story.id);
            enrichedStories.push({
              ...story,
              comments: storyComments,
              reactions: storyReactions
            });
          });

          db.get("SELECT * FROM battles ORDER BY created_at DESC LIMIT 1", (err, battle) => {
            if (err) return res.status(500).send("Error loading battle");
            res.render('index', { stories: enrichedStories, topFans, battle });
          });
        });
      });
    });
  });
});

app.post('/stories/:id/react', (req, res) => {
  const { id } = req.params;
  const { reaction_type } = req.body;
  const username = req.session.user?.username;

  if (!username) return res.status(401).send("Login required");

  db.run("INSERT OR REPLACE INTO story_reactions (story_id, username, reaction_type) VALUES (?, ?, ?)",
    [id, username, reaction_type], err => {
      if (err) return res.status(500).send("Failed to react");
      res.json({ success: true });
    });
});

app.post('/stories/:id/comment', (req, res) => {
  const { id } = req.params;
  const { comment } = req.body;
  const username = req.session.user?.username;

  if (!username || !comment?.trim()) return res.status(400).send("Login required or empty comment");

  const timestamp = new Date().toISOString();
  db.run("INSERT INTO story_comments (story_id, username, comment, timestamp) VALUES (?, ?, ?, ?)",
    [id, username, comment.trim(), timestamp], err => {
      if (err) return res.status(500).send("Failed to comment");
      res.redirect('/');
    });
});
