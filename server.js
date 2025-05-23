const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const bodyParser = require('body-parser');
const multer = require('multer');
const dayjs = require('dayjs');
const relativeTime = require('dayjs/plugin/relativeTime');
const session = require('express-session');
const bcrypt = require('bcrypt');
const admin = require('firebase-admin');
const teamToLeagueMap = require('./teamToLeagueMap');

require('dotenv').config();

dayjs.extend(relativeTime);

const decoded = Buffer.from(process.env.FIREBASE_KEY_BASE64, 'base64').toString('utf8');
admin.initializeApp({ credential: admin.credential.cert(JSON.parse(decoded)) });
const db = admin.firestore();

(async () => {
  try {
    const test = await db.listCollections();
    console.log(`✅ Firestore connected. Collections: ${test.map(col => col.id).join(', ') || 'none yet'}`);
  } catch (err) {
    console.error('❌ Firestore connection failed:', err);
  }
})();

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = process.env.PORT || 3000;

server.listen(PORT, '0.0.0.0', () => console.log(`🚀 Server is UP on port ${PORT}`));

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

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/uploads/'),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${Math.random().toString(36).substring(7)}${path.extname(file.originalname)}`)
});
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });
const multiUpload = upload.fields([
  { name: 'media', maxCount: 1 },
  { name: 'profile_pic', maxCount: 1 },
  { name: 'tacticImage', maxCount: 1 } // ✅ required for tactical board
]);

// ✅ First middleware: fetch unread messages
app.use(async (req, res, next) => {
  try {
    if (req.session.user?.username) {
      const msgSnap = await db.collection('messages')
        .where('receiver', '==', req.session.user.username)
        .where('seenByReceiver', '==', false)
        .get();
      req.session.user.unreadCount = msgSnap.size;
    }
  } catch (err) {
    console.error('User session middleware error:', err);
  }
  next(); // ✅ don't forget this!
});

// ✅ Second middleware: locals for all views
app.use((req, res, next) => {
  res.locals.user = req.session.user;
  res.locals.request = req;
  res.locals.loginError = null;
  res.locals.signupError = null;
  res.locals.hideAuthModals = false; // ✅ This line fixes your current issue
  next();
});

// --- Reusable Homepage Error Renderer ---
async function renderHomeWithError(res, errorType, errorMsg) {
  try {
    const cutoff = dayjs().subtract(24, 'hour').toDate();

    const commentsSnap = await db.collection('comments').get();
    const userStats = {};
    commentsSnap.forEach(doc => {
      const c = doc.data();
      if (!userStats[c.user]) userStats[c.user] = { comments: 0, likes: 0 };
      userStats[c.user].comments += 1;
      userStats[c.user].likes += c.like_reactions || 0;
    });

    const topFans = Object.entries(userStats)
      .sort((a, b) => b[1].likes - a[1].likes)
      .slice(0, 5)
      .map(([username, stats]) => ({ username, comments: stats.comments, likes: stats.likes }));

    const storiesSnap = await db.collection('stories').where('createdAt', '>=', cutoff).orderBy('createdAt', 'desc').get();
    const stories = [];
    for (const doc of storiesSnap.docs) {
      const story = doc.data();
      const commentsSnap = await db.collection('stories').doc(doc.id).collection('comments').get();
      const reactionsSnap = await db.collection('stories').doc(doc.id).collection('reactions').get();

      const reactions = {};
      reactionsSnap.forEach(r => {
        const { reaction_type } = r.data();
        reactions[reaction_type] = (reactions[reaction_type] || 0) + 1;
      });

      stories.push({
        ...story,
        relativeTime: dayjs(story.createdAt.toDate()).fromNow(),
        comments: commentsSnap.docs.map(c => c.data()),
        reactions: Object.entries(reactions).map(([type, count]) => ({ type, count }))
      });
    }

    const battleSnap = await db.collection('battles').orderBy('created_at', 'desc').limit(1).get();
    const battle = battleSnap.docs[0]?.data() || null;

    const data = {
      stories,
      topFans,
      battle,
      loginError: null,
      signupError: null
    };

    data[errorType] = errorMsg;

    res.render('index', data);
  } catch (err) {
    console.error('renderHomeWithError failed:', err);
    res.status(500).send('Failed to load homepage');
  }
}

// --- Signup ---
app.post('/signup', async (req, res) => {
  const { username, password, confirmPassword } = req.body;

  if (!username || !password || !confirmPassword) {
    return renderHomeWithError(res, 'signupError', 'All fields are required.');
  }

  if (password !== confirmPassword) {
    return renderHomeWithError(res, 'signupError', 'Passwords do not match.');
  }

  try {
    const userDoc = await db.collection('users').doc(username).get();
    if (userDoc.exists) {
      return renderHomeWithError(res, 'signupError', 'Username already taken.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await db.collection('users').doc(username).set({
      username,
      password: hashedPassword,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    req.session.user = { username };
    res.redirect('/');
  } catch (err) {
    console.error('Signup error:', err);
    return renderHomeWithError(res, 'signupError', 'Internal server error.');
  }
});

// --- Login ---
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return renderHomeWithError(res, 'loginError', 'Username and password are required.');
  }

  try {
    const userDoc = await db.collection('users').doc(username).get();
    if (!userDoc.exists) {
      return renderHomeWithError(res, 'loginError', 'User not found.');
    }

    const userData = userDoc.data();
    const passwordMatch = await bcrypt.compare(password, userData.password);

    if (!passwordMatch) {
      return renderHomeWithError(res, 'loginError', 'Incorrect password.');
    }

    req.session.user = { username: userData.username };
    res.redirect('/');
  } catch (err) {
    console.error('Login error:', err);
    return renderHomeWithError(res, 'loginError', 'Internal server error.');
  }
});

// --- Logout ---
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) console.error('Logout error:', err);
    res.redirect('/');
  });
});

// --- Home Page ---
app.get('/', async (req, res) => {
  const cutoff = dayjs().subtract(24, 'hour').toDate();

  try {
    const commentsSnap = await db.collection('comments').get();
    const userStats = {};
    commentsSnap.forEach(doc => {
      const c = doc.data();
      if (!userStats[c.user]) userStats[c.user] = { comments: 0, likes: 0 };
      userStats[c.user].comments += 1;
      userStats[c.user].likes += c.like_reactions || 0;
    });

    const topFans = Object.entries(userStats)
      .sort((a, b) => b[1].likes - a[1].likes)
      .slice(0, 5)
      .map(([username, stats]) => ({ username, comments: stats.comments, likes: stats.likes }));

    const storiesSnap = await db.collection('stories').where('createdAt', '>=', cutoff).orderBy('createdAt', 'desc').get();
    const stories = [];
    for (const doc of storiesSnap.docs) {
      const story = doc.data();
      const commentsSnap = await db.collection('stories').doc(doc.id).collection('comments').get();
      const reactionsSnap = await db.collection('stories').doc(doc.id).collection('reactions').get();

      const reactions = {};
      reactionsSnap.forEach(r => {
        const { reaction_type } = r.data();
        reactions[reaction_type] = (reactions[reaction_type] || 0) + 1;
      });

      stories.push({
        ...story,
        relativeTime: dayjs(story.createdAt.toDate()).fromNow(),
        comments: commentsSnap.docs.map(c => c.data()),
        reactions: Object.entries(reactions).map(([type, count]) => ({ type, count }))
      });
    }

    const battleSnap = await db.collection('battles').orderBy('created_at', 'desc').limit(1).get();
    const battle = battleSnap.docs[0]?.data() || null;

    res.render('index', { 
  user: req.session.user || null, // ✅ now it works!
  stories, 
  topFans, 
  battle, 
  signupError: null, 
  loginError: null 
});
  } catch (err) {
    console.error('❌ Home load error:', err);
    res.status(500).send("Failed to load homepage");
  }
});
// --- Upload Story ---
app.post('/stories/upload', upload.single('storyMedia'), async (req, res) => {
  if (!req.session.user) return res.redirect('/?error=Login required');
  if (!req.file) return res.redirect('/?error=No file uploaded');

  const filePath = `/uploads/${req.file.filename}`;
  const username = req.session.user.username;
  const caption = req.body.caption || '';

  try {
    await db.collection('stories').add({
      image: filePath,
      username,
      caption,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    res.redirect('/');
  } catch (err) {
    console.error('Error saving story:', err);
    res.redirect('/?error=Failed to save story');
  }
});

// --- React to Story ---
app.post('/stories/:id/react', async (req, res) => {
  const { id } = req.params;
  const { reaction_type } = req.body;
  const username = req.session.user?.username;

  if (!username || !reaction_type) return res.status(400).send("Login or reaction missing");

  try {
    const reactionRef = db.collection('stories').doc(id).collection('reactions').doc(`${username}_${reaction_type}`);
    await reactionRef.set({ username, reaction_type });
    res.json({ success: true });
  } catch (err) {
    console.error('Story react error:', err);
    res.status(500).send("Failed to react");
  }
});

// --- Comment on Story ---
app.post('/stories/:id/comment', async (req, res) => {
  const { id } = req.params;
  const { comment } = req.body;
  const username = req.session.user?.username;

  if (!username || !comment?.trim()) return res.status(400).send("Login or comment missing");

  try {
    await db.collection('stories').doc(id).collection('comments').add({
      username,
      comment: comment.trim(),
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    res.redirect('/');
  } catch (err) {
    console.error('Story comment error:', err);
    res.status(500).send("Failed to comment");
  }
});

// --- Team Comments ---
app.post('/team/:teamname/comment', multiUpload, async (req, res) => {
  if (!req.session.user) return res.status(401).send("Login required");

  const { teamname } = req.params;
  const { text } = req.body;

  const media =
    req.files?.media?.[0]?.path?.includes('uploads')
      ? `/uploads/${req.files.media[0].filename}`
      : req.files?.tacticImage?.[0]
      ? `/uploads/${req.files.tacticImage[0].filename}`
      : '';

  const profilePic = req.files?.profile_pic
    ? `/uploads/${req.files.profile_pic[0].filename}`
    : '';

  // ✅ Allow comment if text or media is present
  if (!text?.trim() && !media) {
    return res.status(400).send("Comment must include text or an image");
  }

  try {
    await db.collection('comments').add({
      team: teamname,
      user: req.session.user.username,
      text: text?.trim() || '', // ensure string even if empty
      media,
      profile_pic: profilePic,
      like_reactions: 0,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    res.redirect(`/team/${teamname}`);
  } catch (err) {
    console.error('Team comment error:', err);
    res.status(500).send("Failed to post comment");
  }
});

// --- Team Page ---
app.get('/team/:teamname', async (req, res) => {
  const { teamname } = req.params;
  const sortField = req.query.sort === 'top' ? 'like_reactions' : 'timestamp';

  const leagueInfo = teamToLeagueMap[teamname];
  if (!leagueInfo) {
    console.error('❌ Unknown team:', teamname);
    return res.status(404).send('Team not found');
  }

  try {
    let commentsRef = db.collection('comments').where('team', '==', teamname);

    // Only add ordering if field is guaranteed to exist on all docs
    if (sortField === 'like_reactions') {
      commentsRef = commentsRef.orderBy('like_reactions', 'desc');
    } else {
      commentsRef = commentsRef.orderBy('timestamp', 'desc');
    }

    const snapshot = await commentsRef.get();
    const comments = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

    res.render('team', {
      teamname,
      comments,
      sort: req.query.sort,
      useTeamHeader: true,
      leagueSlug: leagueInfo.slug,
      leagueName: leagueInfo.name
    });
  } catch (err) {
    console.error('❌ Team page error:', err.message);
    res.status(500).send('Failed to load team page');
  }
});

// --- Comment Reaction ---
app.post('/comment/:id/react/:type', async (req, res) => {
  const { id, type } = req.params;
  const validTypes = ['like', 'funny', 'angry', 'love'];

  if (!validTypes.includes(type)) return res.status(400).json({ success: false, message: 'Invalid reaction' });

  try {
    const commentRef = db.collection('comments').doc(id);
    await commentRef.update({ [`${type}_reactions`]: admin.firestore.FieldValue.increment(1) });
    res.json({ success: true });
  } catch (err) {
    console.error('React error:', err);
    res.status(500).json({ success: false });
  }
});

// --- Fan Battle Voting ---
app.post('/battle/vote', async (req, res) => {
  const { battleId, vote } = req.body;
  const username = req.session.user?.username;

  if (!username || !vote) return res.status(400).json({ success: false, message: 'Missing data' });

  try {
    const voteRef = db.collection('battles').doc(battleId).collection('votes').doc(username);
    const voteSnap = await voteRef.get();

    if (voteSnap.exists) return res.json({ success: false, message: 'Already voted' });

    await voteRef.set({ username, voted_for: vote });
    const battleRef = db.collection('battles').doc(battleId);
    await battleRef.update({ [vote === 'team1' ? 'votes_team1' : 'votes_team2']: admin.firestore.FieldValue.increment(1) });

    res.json({ success: true });
  } catch (err) {
    console.error('Vote error:', err);
    res.status(500).json({ success: false, message: 'Vote failed' });
  }
});
// --- User Profile Page ---
app.get('/user/:username', async (req, res) => {
  const { username } = req.params;

  try {
    const commentsSnap = await db.collection('comments')
  .where('user', '==', username)
  .get(); // removed .orderBy

    const comments = commentsSnap.docs.map(doc => ({ ...doc.data() }));
    const totalComments = comments.length;
    const totalLikes = comments.reduce((sum, c) => sum + (c.like_reactions || 0), 0);

    const enrichedComments = comments.map(c => ({
      ...c,
      relativeTime: c.timestamp ? dayjs(c.timestamp.toDate()).fromNow() : ''
    }));

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

// ✅ Helper: Save message to Firestore
async function saveMessage({ sender, receiver, content }) {
  const timestamp = new Date();

  const message = {
    sender,
    receiver,
    participants: [sender, receiver],
    content: content.trim(),
    timestamp: admin.firestore.Timestamp.fromDate(timestamp),
    seenByReceiver: false
  };

  const ref = await db.collection('messages').add(message);
  return { id: ref.id, ...message };
}

// ✅ API: Send message
app.post('/api/messages/send', async (req, res) => {
  const sender = req.session.user?.username;
  const { receiver, content } = req.body;
  if (!sender || !receiver || !content?.trim()) {
    return res.status(400).json({ success: false });
  }

  try {
    const saved = await saveMessage({ sender, receiver, content });
    res.json({ success: true, message: saved });
  } catch (err) {
    console.error('❌ Failed to send message:', err);
    res.status(500).json({ success: false });
  }
});

// ✅ API: Get conversation
app.get('/api/messages/conversation/:username', async (req, res) => {
  const currentUser = req.session.user?.username;
  const otherUser = req.params.username;

  if (!currentUser) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  try {
    const snapshot = await db.collection('messages')
      .where('sender', 'in', [currentUser, otherUser])
      .where('receiver', 'in', [currentUser, otherUser])
      .orderBy('timestamp', 'asc')  // <-- MUST match index direction
      .get();

    const messages = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data()
    }));

    res.json(messages);
  } catch (err) {
    console.error('❌ Failed to fetch messages:', err);
    res.status(500).json({ success: false, message: 'Failed to fetch messages' });
  }
});

// ✅ Inbox
app.get('/inbox', async (req, res) => {
  if (!req.session.user) return res.redirect('/?error=Login required');
  const username = req.session.user.username;
  const currentUser = req.session.user;

  try {
    const snapshot = await db.collection('messages')
      .where('participants', 'array-contains', username)
      .orderBy('timestamp', 'desc')
      .get();

    const conversations = {};
    snapshot.forEach(doc => {
      const msg = doc.data();
      const otherUser = msg.sender === username ? msg.receiver : msg.sender;

      if (!conversations[otherUser] || msg.timestamp?.toMillis?.() > conversations[otherUser].timestamp?.toMillis?.()) {
        conversations[otherUser] = {
          user: otherUser,
          lastMessage: msg.content,
          timestamp: msg.timestamp?.toDate?.() || new Date(0),
          seenByReceiver: msg.seenByReceiver || false,
          profile_pic: msg.profile_pic || null
        };
      }
    });

    const sorted = Object.values(conversations).sort((a, b) => b.timestamp - a.timestamp);
    res.render('inbox', { conversations: sorted, currentUser });
  } catch (err) {
    console.error('❌ Inbox error:', err);
    res.status(500).send("Inbox error");
  }
});

// ✅ Chat Page
app.get('/chat/:username', async (req, res) => {
  if (!req.session.user) return res.redirect('/?error=Login required');

  const sender = req.session.user.username;
  const receiver = req.params.username;
  if (sender === receiver) return res.redirect('/?error=Cannot chat with yourself');

  try {
    const userSnap = await db.collection('users').doc(receiver).get();
    if (!userSnap.exists) return res.status(404).send("User not found");

    const unseen = await db.collection('messages')
      .where('sender', '==', receiver)
      .where('receiver', '==', sender)
      .where('seenByReceiver', '==', false)
      .get();

    await Promise.all(unseen.docs.map(doc => doc.ref.update({ seenByReceiver: true })));

    res.render('chat', {
      receiver: userSnap.data(),
      currentUser: req.session.user
    });
  } catch (err) {
    console.error('❌ Chat load error:', err);
    res.status(500).send("Failed to load chat");
  }
});

// ✅ WebSocket
const connectedUsers = new Map();

io.on('connection', (socket) => {
  console.log('🔌 Socket connected:', socket.id);

  socket.on('joinRoom', ({ sender, receiver }) => {
    const room = [sender, receiver].sort().join('-');
    socket.join(room);
    connectedUsers.set(sender, socket.id);
    socket.broadcast.emit('userOnline', { username: sender });
  });

  socket.on('chatMessage', async ({ sender, receiver, content }) => {
    if (!sender || !receiver || !content?.trim()) return;
    const room = [sender, receiver].sort().join('-');

    try {
      const saved = await saveMessage({ sender, receiver, content });
      io.to(room).emit('newMessage', saved);
    } catch (err) {
      console.error('❌ Socket message save error:', err);
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

  socket.on('disconnect', () => {
    for (const [username, id] of connectedUsers.entries()) {
      if (id === socket.id) {
        connectedUsers.delete(username);
        socket.broadcast.emit('userOffline', { username });
        break;
      }
    }
    console.log('❌ Socket disconnected:', socket.id);
  });
});

//Leagues 
app.get('/premier.html', (req, res) => res.render('premier'));
app.get('/laliga.html', (req, res) => res.render('laliga'));
app.get('/serie-a.html', (req, res) => res.render('serie-a'));
app.get('/bundesliga.html', (req, res) => res.render('bundesliga'));
app.get('/ligue1.html', (req, res) => res.render('ligue1'));
app.get('/roshn-saudi.html', (req, res) => res.render('roshn-saudi'));
app.get('/eredivisie.html', (req, res) => res.render('eredivisie'));
app.get('/liga-portugal.html', (req, res) => res.render('liga-portugal'));
app.get('/super-lig.html', (req, res) => res.render('super-lig'));
