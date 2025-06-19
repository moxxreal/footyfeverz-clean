const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const multer = require('multer');
const dayjs = require('dayjs');
const relativeTime = require('dayjs/plugin/relativeTime');
const session = require('express-session');
const bcrypt = require('bcrypt');
const admin = require('firebase-admin');
const teamToLeagueMap = require('./teamToLeagueMap');
const sanitizeHtml = require('sanitize-html');
const teamImages = require('./teamImages');
const http = require('http');
const { Server } = require('socket.io');


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
const PORT = process.env.PORT || 3000;

// ─── Session setup ──────────────────────────────────────────────────────────
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'super-secret-key',
  resave: false,
  saveUninitialized: true
});
app.use(sessionMiddleware);

// Create HTTP server and Socket.IO server
const server = http.createServer(app);
const io = new Server(server);

// --- Chat notification middleware ---
app.use(async (req, res, next) => {
  try {
    if (req.session.user?.username) {
      const username = req.session.user.username;
      const chatsSnap = await db.collection('chats')
        .where(`participants.${username}.unreadCount`, '>', 0)
        .get();
      req.session.user.chatNotifications = chatsSnap.size;
    }
  } catch (err) {
    console.error('Chat notification middleware error:', err);
  }
  next();
});

// --- List of chats (inbox/chats) ---
app.get('/inbox/chats', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const me = req.session.user.username;
  const chatDocs = await db.collection('chats')
    .where(`participants.${me}`, '!=', null)
    .get();

  const chats = chatDocs.docs.map(doc => {
    const data = doc.data();
    const other = Object.keys(data.participants).find(u => u !== me);
    return { username: other, unread: data.participants[me].unreadCount || 0 };
  });

  res.render('inbox-chats', {
    user: req.session.user,
    request: req,             // so header can read request.originalUrl
    loginError: null,         // satisfy header’s loginError check
    signupError: null,        // satisfy header’s signupError check
    showAuthLinks: true,      // show “Sign Up” / “Login” if you want
    showLeagueLink: false,
    useTeamHeader: false,
    chats
  });
});

// --- Single chat page ---
app.get('/chat/:other', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  const me     = req.session.user.username;
  const other  = req.params.other;
  const chatId = [me, other].sort().join('_');
  const chatRef = db.collection('chats').doc(chatId);

  // Load existing messages or initialize chat
  const chatDoc = await chatRef.get();
  let messages = [];

  if (chatDoc.exists) {
    const snap = await chatRef
      .collection('messages')
      .orderBy('timestamp', 'asc')
      .get();
    messages = snap.docs.map(d => d.data());

    // Reset my unread count
    await chatRef.update({
      [`participants.${me}.unreadCount`]: 0
    });
  } else {
    // Create new chat document with both participants
    await chatRef.set({
      participants: {
        [me]:    { unreadCount: 0 },
        [other]: { unreadCount: 0 }
      }
    });
  }

  // Render the chat view, passing all header/context vars
  res.render('chat', {
    user:          req.session.user,
    request:       req,           // for request.originalUrl in header
    loginError:    null,          // satisfy header checks
    signupError:   null,
    showAuthLinks: true,          // toggle as desired
    showLeagueLink: false,
    useTeamHeader: false,
    other,
    messages
  });
});

// --- Socket.IO live chat ---
io.on('connection', socket => {
  socket.on('join', room => socket.join(room));

  socket.on('message', async ({ room, from, to, text }) => {
    const timestamp = admin.firestore.FieldValue.serverTimestamp();
    const chatRef = db.collection('chats').doc(room);

    // persist message
    await chatRef.collection('messages').add({ from, to, text, timestamp });
    // bump unread count
    await chatRef.update({
      [`participants.${to}.unreadCount`]: admin.firestore.FieldValue.increment(1)
    });

    // broadcast
    io.to(room).emit('message', { from, text, timestamp: Date.now() });
  });
});

// Replace your app.listen with:
server.listen(PORT, () => console.log(`🚀 Server UP on port ${PORT}`));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.json({ limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function computeFeverScore(fever) {
  const ageHours = (Date.now() - fever.createdAt.toDate().getTime()) / 36e5;
  // simple: each like + comment gives 10 points, decays 2 points per hour
  return (fever.likes + fever.comments) * 10 - ageHours * 2;
}

// Storage engine with sanitized filename
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/uploads/'),
  filename: (req, file, cb) => {
    const cleanName = path.basename(file.originalname);
    const ext = path.extname(cleanName);
    const filename = `${Date.now()}-${Math.random().toString(36).substring(7)}${ext}`;
    cb(null, filename);
  }
});

// Accept only images and videos (optional but recommended)
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/quicktime'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Unsupported file type'), false);
  }
};

// Upload config
const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 50 * 1024 * 1024 } // 50MB max
});

// Multi-field upload for comments, profiles, tactical images, fevers etc
const multiUpload = upload.fields([
  { name: 'media', maxCount: 1 },
  { name: 'profile_pic', maxCount: 1 },
  { name: 'tacticImage', maxCount: 1 },
  { name: 'feverMedia', maxCount: 1 }
]);

// Firestore document: fevers/{feverId}
// {
//   user:      "alice",
//   caption:   "Epic goal celebration!",
//   mediaURL:  "/uploads/1623456789-1a2b3c.gif",
//   mediaType: "video" | "image",
//   createdAt: FieldValue.serverTimestamp(),
//   likes:     0,
//   comments:  0
// }

//fevers
app.post('/fever', multiUpload, async (req, res) => {
  if (!req.session.user) return res.status(401).send("Login required");

  const file = req.files?.feverMedia?.[0];
  if (!file) return res.status(400).send("Please upload an image or video");

  const mediaURL = `/uploads/${file.filename}`;
  const mediaType = file.mimetype.startsWith('video/') ? 'video' : 'image';
  const caption = sanitizeHtml(req.body.caption || '');

  try {
    await db.collection('fevers').add({
      user: req.session.user.username,
      caption,
      mediaURL,
      mediaType,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      likes: 0,
      comments: 0
    });
    res.redirect('/');
  } catch (err) {
    console.error('Fever post error:', err);
    res.status(500).send("Could not post your Fever");
  }
});

app.get('/api/fevers', async (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 10;
  const lastCreated = req.query.lastCreated; // ISO string

  // 1) Fetch up to 50 documents ordered by Timestamp
  let query = db.collection('fevers')
    .orderBy('createdAt', 'desc')
    .limit(50);

  if (lastCreated) {
    query = query.startAfter(
      admin.firestore.Timestamp.fromDate(new Date(lastCreated))
    );
  }

  const snap = await query.get();

  // 2) Map to keep the raw Timestamp around for scoring
  const fevers = snap.docs.map(doc => {
    const data = doc.data();
    return {
      id: doc.id,
      user: data.user,
      caption: data.caption,
      mediaURL: data.mediaURL,
      mediaType: data.mediaType,
      likes: data.likes,
      comments: data.comments,
      createdAtTimestamp: data.createdAt,            // Firestore Timestamp
    };
  });

  // 3) Compute score using the Timestamp
  fevers.forEach(f => {
    f.score = computeFeverScore({ 
      likes: f.likes, 
      comments: f.comments, 
      createdAt: f.createdAtTimestamp 
    });
  });

  // 4) Sort by score descending
  fevers.sort((a, b) => b.score - a.score);

  // 5) Trim to the client’s requested page size
  const page = fevers.slice(0, limit);

  // 6) Convert for JSON output (timestamps → ISO strings)
  const output = page.map(f => ({
    id: f.id,
    user: f.user,
    caption: f.caption,
    mediaURL: f.mediaURL,
    mediaType: f.mediaType,
    likes: f.likes,
    comments: f.comments,
    createdAt: f.createdAtTimestamp.toDate().toISOString(),
    score: f.score
  }));

  res.json(output);
});
// ─── Fetch comments for a fever ─────────────────────────────────────────────
app.get('/api/fevers/:id/comments', async (req, res) => {
  try {
    const snap = await db.collection('feverComments')
      .where('feverId', '==', req.params.id)
      .orderBy('timestamp', 'asc')
      .get();

    const comments = snap.docs.map(doc => {
      const d = doc.data();
      return {
        id: doc.id,
        user: d.user,
        text: d.text,
        timestamp: d.timestamp.toDate().toISOString()
      };
    });
    res.json(comments);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load comments' });
  }
});

// ─── Post a new comment on a fever ─────────────────────────────────────────
app.post('/api/fevers/:id/comments', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Login required' });
  const { text } = req.body;
  if (!text?.trim()) return res.status(400).json({ error: 'Comment cannot be empty' });

  try {
    const comment = {
      feverId: req.params.id,
      user: req.session.user.username,
      text: sanitizeHtml(text),
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    };
    const ref = await db.collection('feverComments').add(comment);
    res.json({ id: ref.id, ...comment, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to post comment' });
  }
});

// ─── Like a fever (1 per user) ───────────────────────────────────────────
app.post('/api/fevers/:id/like', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Login required' });

  const feverId = req.params.id;
  const username = req.session.user.username;

  const likeDocRef = db
    .collection('fevers')
    .doc(feverId)
    .collection('likes')
    .doc(username);

  try {
    const likeDoc = await likeDocRef.get();
    if (likeDoc.exists) {
      // already liked
      const feverSnap = await db.collection('fevers').doc(feverId).get();
      return res.json({ likes: feverSnap.data().likes, alreadyLiked: true });
    }

    // record the user’s like
    await likeDocRef.set({ timestamp: admin.firestore.FieldValue.serverTimestamp() });

    // increment the fever’s total
    const feverRef = db.collection('fevers').doc(feverId);
    await feverRef.update({ likes: admin.firestore.FieldValue.increment(1) });

    const updated = await feverRef.get();
    res.json({ likes: updated.data().likes, alreadyLiked: false });
  } catch (err) {
    console.error('Like error:', err);
    res.status(500).json({ error: 'Could not like' });
  }
});

// ─── (Optional) Serve a single fever page for sharing ──────────────────────
app.get('/fever/:id', async (req, res) => {
  try {
    const doc = await db.collection('fevers').doc(req.params.id).get();
    if (!doc.exists) return res.status(404).send('Not found');
    const f = doc.data();
    res.render('fever-share', { fever: { id: doc.id, ...f, createdAt: f.createdAt.toDate() } });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error');
  }
});

// ✅ First middleware: fetch unread messages
app.use(async (req, res, next) => {
  try {
    if (req.session.user?.username) {
      const username = req.session.user.username;

      // Count pending follow requests (if you store them in a subcollection)
      const followSnap = await db.collection('users')
        .doc(username)
        .collection('followRequests')
        .get();
      req.session.user.followNotifications = followSnap.size;
    }
  } catch (err) {
    console.error('User session middleware error:', err);
  }
  next();
});

// ✅ Second middleware: locals for all views
app.use((req, res, next) => {
  res.locals.user = req.session.user;
  res.locals.request = req;
  res.locals.loginError = null;
  res.locals.signupError = null;
  res.locals.hideAuthModals = false;
  res.locals.chatNotifications  = req.session.user?.chatNotifications || 0;
  next();
});

async function loadHomeData() {
  const statsSnap = await db
    .collection('userStats')
    .get();
let topFans = statsSnap.docs.map(doc => {
  const data = doc.data();
  return {
    username: doc.id,
    comments: data.comments || 0,
     likes:
       (data.like  || data.likes  || 0) +
       (data.funny || 0) +
       (data.angry || 0) +
       (data.love  || 0)
  };
});
topFans.forEach(fan => {
  fan.score = fan.comments * 5 + fan.likes;
});
topFans.sort((a, b) => b.score - a.score);
topFans = topFans.slice(0, 5);

  return {topFans};
}

// --- Reusable Homepage Error Renderer ---
async function renderHomeWithError(res, errorType, errorMsg) {
  try {
    const { topFans } = await loadHomeData();

    const data = {
      topFans,
      loginError: null,
      signupError: null
    };

    data[errorType] = errorMsg; // e.g., data.signupError = "..."
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

    // ✅ Create user document
    await db.collection('users').doc(username).set({
      username,
      password: hashedPassword,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // ✅ Initialize userStats document
    await db.collection('userStats').doc(username).set({
      comments: 0,
      likes: 0,
      funny: 0,
      angry: 0,
      love: 0,
      score: 0
    });

    // ✅ Set session
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
  try {
    const {topFans} = await loadHomeData();

    let user = req.session.user || null;

    if (user) {
      const username = user.username;

      const tagSnap = await db.collection('tags')
        .where('taggedUserId', '==', username)
        .where('seen', '==', false)
        .get();

      user = {
        ...user,
        tagNotifications: tagSnap.size,
        // if you still use unreadCount elsewhere, you can set it to tags only:
        unreadCount: tagSnap.size
     };
    }

    res.render('index', {
      user,
      topFans,
      signupError: null,
      loginError: null
    });
  } catch (err) {
    console.error('❌ Home load error:', err);
    res.status(500).send("Failed to load homepage");
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

  let profilePic = '';
  const userDoc = await db.collection('users').doc(req.session.user.username).get();
  if (userDoc.exists) {
    profilePic = userDoc.data().profile_pic || '';
  }

  // ✅ Allow comment if text or media is present
  if (!text?.trim() && !media) {
    return res.status(400).send("Comment must include text or an image");
  }

  try {
    const trimmedText = text.trim();

    // 🔽 Save the comment
await db.collection('comments').add({
  team: teamname,
  user: req.session.user.username,
  text: trimmedText,
  media,
  profile_pic: profilePic,
  like_reactions: 0,
  timestamp: admin.firestore.FieldValue.serverTimestamp()
});
await db.collection('userStats').doc(req.session.user.username).set({
  comments: admin.firestore.FieldValue.increment(1),
  likes: 0,
  funny: 0,
  angry: 0,
  love: 0,
  score: admin.firestore.FieldValue.increment(1)
}, { merge: true });


    // ✅ Mention tagging logic
    const mentionedUsernames = [...trimmedText.matchAll(/@(\w+)/g)].map(match => match[1]);

    for (const username of mentionedUsernames) {
      const tag = {
        fromUser: req.session.user.username,
        taggedUserId: username,
        content: trimmedText,
        timestamp: new Date(),
        threadType: 'team',
        link: `/team/${teamname}#comments`,
        seen: false
      };
      await db.collection('tags').add(tag);
    }

    res.redirect(`/team/${teamname}#comments`);
  } catch (err) {
    console.error('Team comment error:', err);
    res.status(500).send("Failed to post comment");
  }
});

//-----Poke-rival
app.post('/poke-rival', multiUpload, async (req, res) => {
  if (!req.session.user) return res.status(401).send("Login required");

  const { teamA, teamB, text } = req.body;
  const username = req.session.user.username;

  if (!teamA || !teamB || !text?.trim()) {
    return res.status(400).send("Missing data");
  }

  const media =
    req.files?.media?.[0]?.path?.includes('uploads')
      ? `/uploads/${req.files.media[0].filename}`
      : '';

  try {
    const fourHoursAgo = new Date(Date.now() - 4 * 60 * 60 * 1000);

    // 🔁 Reverse rivalry check (teamB vs teamA)
    const reverseCheck = await db.collection('rivalPokes')
      .where('createdAt', '>', fourHoursAgo)
      .where('teamA', '==', teamB)
      .where('teamB', '==', teamA)
      .get();

    if (!reverseCheck.empty) {
      return res.status(400).json({
        error: "A reverse rivalry is already active. Please wait until it expires."
      });
    }

    // ⏱️ Same direction rivalry check
    const sameCheck = await db.collection('rivalPokes')
      .where('createdAt', '>', fourHoursAgo)
      .where('teamA', '==', teamA)
      .where('teamB', '==', teamB)
      .get();

    if (!sameCheck.empty) {
      return res.status(400).json({
        error: 'An active rivalry already exists between these two teams. Please wait until it expires.'
      });
    }

        // ✅ Save the poke thread (with expiresAt for 4-hour TTL)
    const now       = admin.firestore.Timestamp.now();
    const expiresAt = admin.firestore.Timestamp.fromMillis(
      Date.now() + 4 * 60 * 60 * 1000
    );

    const newDocRef = await db.collection('rivalPokes').add({
      teamA,
      teamB,
      createdBy: username,
      text: text.trim(),
      media,
      createdAt: now,
      expiresAt,              // ← new field for TTL
      score: { teamA: 0, teamB: 0 }
    });

    const pokeId = newDocRef.id;

    // ✅ Detect @username mentions and add tag notifications
    const mentionedUsernames = [...text.matchAll(/@(\w+)/g)].map(match => match[1]);

    for (const taggedUser of mentionedUsernames) {
      const tag = {
        fromUser: username,
        taggedUserId: taggedUser,
        content: text,
        timestamp: new Date(),
        threadType: 'poke',
        link: `/poke/${pokeId}#comments`,
        seen: false
      };
      await db.collection('tags').add(tag);
    }

    res.redirect(`/team/${teamA}`);
  } catch (err) {
    console.error('❌ Failed to poke rival:', err);
    res.status(500).send("Failed to poke rival");
  }
});

// --- Team Page ---
app.get('/team/:teamname', async (req, res) => {
  const { teamname } = req.params;

  const leagueInfo = teamToLeagueMap[teamname];
  if (!leagueInfo) {
    console.error('❌ Unknown team:', teamname);
    return res.status(404).send('Team not found');
  }

  const leagueSlug = leagueInfo.slug;
  const leagueName = leagueInfo.name;

  try {
    // Build image path dynamically
    const imagePath = `/images/teams/${leagueSlug}/${teamname}.png`;

    // Parse pagination & sort from query (with defaults)
    const page = parseInt(req.query.page, 10) || 1;
    const sort = req.query.sort || 'new';

    const limit  = 40;
    const offset = (page - 1) * limit;

    // Fetch all comments for the team (then paginate in memory)
    const commentsRef = db.collection('comments')
      .where('team', '==', teamname)
      .orderBy('timestamp', 'desc');
    const snapshot = await commentsRef.get();
    const allDocs  = snapshot.docs;

    const paginatedDocs = allDocs.slice(offset, offset + limit);
    const comments = paginatedDocs.map(doc => {
      const data = doc.data();
      return {
        id: doc.id,
        ...data,
        relativeTime: data.timestamp
          ? dayjs(data.timestamp.toDate()).fromNow()
          : ''
      };
    });

    const totalPages = Math.ceil(allDocs.length / limit);

    // Fetch Rival Pokes for this team
    const pokeSnapA = await db.collection('rivalPokes')
      .where('teamA', '==', teamname)
      .get();
    const pokeSnapB = await db.collection('rivalPokes')
      .where('teamB', '==', teamname)
      .get();

    const allPokes = [...pokeSnapA.docs, ...pokeSnapB.docs];
    const fourHoursAgo = new Date(Date.now() - 4 * 60 * 60 * 1000);

    const pokeThreads = allPokes
      .filter(doc => {
        const data = doc.data();
        return data.createdAt?.toDate?.() > fourHoursAgo;
      })
      .sort((a, b) =>
        b.data().createdAt.toMillis() - a.data().createdAt.toMillis()
      )
      .slice(0, 3)
      .map(doc => {
        const data = doc.data();
        return {
          id: doc.id,
          ...data,
          relativeTime: data.createdAt
            ? dayjs(data.createdAt.toDate()).fromNow()
            : '',
          createdAtMillis: data.createdAt?.toMillis?.() || 0
        };
      });

    // Fetch team metadata
    const teamDoc  = await db.collection('teams').doc(teamname).get();
    const teamData = teamDoc.exists ? teamDoc.data() : null;

    // Build simple relative times array if you still need it
    const relativeTimes = comments.map(comment => {
      const ts = comment.timestamp?.toDate?.();
      if (!ts) return 'Just now';
      const diffSeconds = Math.floor((Date.now() - ts) / 1000);
      if (diffSeconds < 60) return `${diffSeconds}s ago`;
      const diffMinutes = Math.floor(diffSeconds / 60);
      if (diffMinutes < 60) return `${diffMinutes}m ago`;
      const diffHours = Math.floor(diffMinutes / 60);
      if (diffHours < 24) return `${diffHours}h ago`;
      const diffDays = Math.floor(diffHours / 24);
      return `${diffDays}d ago`;
    });

    // Render view with page, sort, and all your other vars
    res.render('team', {
      user:            req.session.user || null,
      teamname,
      teamData,
      comments,
      page, 
      sort, 
      totalPages,
      relativeTimes,
      pokeThreads,
      leagueSlug,
      leagueName,
      useTeamHeader:   true,
      imagePath,
      teamToLeagueMap,
      pokeError:       'A reverse rivalry is already active. Please wait until it expires.'
    });

  } catch (err) {
    console.error('❌ Team page error:', err);
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
    const commentDoc = await commentRef.get();
const commentData = commentDoc.data();
const commentUser = commentData.user;

await db.collection('userStats').doc(commentUser).set({
  [type]: admin.firestore.FieldValue.increment(1),
  score: admin.firestore.FieldValue.increment(1)
}, { merge: true });
    res.json({ success: true });
  } catch (err) {
    console.error('React error:', err);
    res.status(500).json({ success: false });
  }
});

// 🔔 Notifications page
app.get('/notifications', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');

  const snapshot = await db.collection('notifications')
    .where('toUser', '==', req.session.user.id)
    .orderBy('timestamp', 'desc')
    .get();

  const notifications = snapshot.docs.map(doc => ({
    id: doc.id,
    ...doc.data()
  }));

  for (const doc of snapshot.docs) {
    await db.collection('notifications').doc(doc.id).update({ read: true });
  }

  res.render('notifications', {
    user: req.session.user,
    notifications
  });
});

// ⚔️ View a Rival Poke thread
app.get('/poke/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const pokeDoc = await db.collection('rivalPokes').doc(id).get();
    if (!pokeDoc.exists) return res.status(404).send("Rival thread not found");

    const pokeData = pokeDoc.data();

    const commentSnap = await db.collection('rivalPokes')
      .doc(id)
      .collection('comments')
      .orderBy('timestamp', 'asc')
      .get();

    const pokeThreadComments = commentSnap.docs.map(c => {
      const data = c.data();
      return {
        ...data,
        relativeTime: data.timestamp ? dayjs(data.timestamp.toDate()).fromNow() : ''
      };
    });

    // ✅ Get user's side (if logged in)
    let userVote = null;
    if (req.session.user) {
      const voteDoc = await db.collection('rivalPokes')
        .doc(id).collection('supporters')
        .doc(req.session.user.username).get();

      if (voteDoc.exists) {
        userVote = voteDoc.data().team;
      }
    }

    res.render('poke-thread', {
      pokeId: id,
      pokeData,
      comments: pokeThreadComments,
      teamA: pokeData.teamA,
      teamB: pokeData.teamB,
      profilePic: req.session.user?.profile_pic || '/default-avatar.png',
      user: req.session.user || null,
      userVote,
      headerClass: 'header-simple',
      useTeamHeader: false
    });
  } catch (err) {
    console.error('❌ Failed to load poke thread:', err);
    res.status(500).send("Failed to load poke thread");
  }
});

// 🔁 Vote count for game rendering
app.get('/poke/:id/votes', async (req, res) => {
  try {
    const { id } = req.params;

    const voteSnap = await db.collection('rivalPokes')
      .doc(id)
      .collection('votes')
      .get();

    let teamA = 0;
    let teamB = 0;

    voteSnap.forEach(doc => {
      const vote = doc.data();
      if (vote.team === 'teamA') teamA++;
      else if (vote.team === 'teamB') teamB++;
    });

    res.json({ teamA, teamB });
  } catch (err) {
    console.error('❌ Failed to fetch poke votes:', err);
    res.status(500).json({ error: 'Failed to get vote counts' });
  }
});

app.post('/poke/:id/support', async (req, res) => {
  const { id } = req.params;
  const { team } = req.body;
  const username = req.session.user?.username;

  if (!username || !['teamA', 'teamB'].includes(team)) {
    return res.status(400).send('Invalid vote');
  }

  try {
    const voteRef = db.collection('rivalPokes').doc(id).collection('votes').doc(username);
    const existingVoteDoc = await voteRef.get();

    if (!existingVoteDoc.exists) {
      // ✅ Save per-user vote
      await voteRef.set({ team });

      // ✅ Increment global vote count
      await db.collection('rivalPokes')
        .doc(id)
        .collection('supportVotes')
        .doc('counts')
        .set({
          [team]: admin.firestore.FieldValue.increment(1)
        }, { merge: true });
    }

    res.redirect(`/poke/${id}`);
  } catch (err) {
    console.error('❌ Failed to record vote:', err);
    res.status(500).send('Could not record vote');
  }
});
app.post('/poke/:id/reset-votes', async (req, res) => {
  const { id } = req.params;
  const { scorer } = req.body; // scorer = "teamA" or "teamB"

  if (!["teamA", "teamB"].includes(scorer)) {
    return res.status(400).send("Invalid scorer");
  }

  try {
    const pokeRef = db.collection('rivalPokes').doc(id);

    // 🔁 Step 1: Delete all individual votes
    const votesSnap = await pokeRef.collection('votes').get();
    const batch = db.batch();
    votesSnap.forEach(doc => batch.delete(doc.ref));
    await batch.commit();

    // 🔁 Step 2: Reset vote counts
    await pokeRef.collection('supportVotes').doc('counts').set({ teamA: 0, teamB: 0 });

    // ✅ Step 3: Increment the scorer’s goal
    const doc = await pokeRef.get();
    const existingScore = doc.data().score || { teamA: 0, teamB: 0 };

    existingScore[scorer] += 1;

    await pokeRef.update({ score: existingScore });

    res.sendStatus(200);
  } catch (err) {
    console.error('❌ Failed to reset and update score:', err);
    res.status(500).send("Failed to process goal");
  }
});

// --- Full comment handler for rival-poke posts (no tagging allowed) ---
app.post('/poke/:id/comment', multiUpload, async (req, res) => {
  const { id } = req.params;
  const { text } = req.body;
  const username = req.session.user?.username;

  if (!username || !text?.trim()) {
    return res.status(400).send("Missing data");
  }

  // Handle uploaded media (image/video)
  const media =
    req.files?.media?.[0]?.path.includes('uploads')
      ? `/uploads/${req.files.media[0].filename}`
      : '';

  try {
    // 1) Determine fan side from existing vote only
    let fanSide = null;
    const voteDoc = await db
      .collection('rivalPokes')
      .doc(id)
      .collection('votes')
      .doc(username)
      .get();

    if (voteDoc.exists) {
      const vote = voteDoc.data().team;
      if (vote === 'teamA') fanSide = 'teamA';
      else if (vote === 'teamB') fanSide = 'teamB';
    }

    // 2) Save the comment under the poke thread, include `team` only when fanSide is set
    const commentData = {
      user: username,
      text: text.trim(),
      media,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
    };
    if (fanSide) commentData.team = fanSide;

    await db
      .collection('rivalPokes')
      .doc(id)
      .collection('comments')
      .add(commentData);

    // 3) Update the user's stats
    await db.collection('userStats').doc(username).set({
      comments: admin.firestore.FieldValue.increment(1),
      likes: 0,
      funny: 0,
      angry: 0,
      love: 0,
      score: admin.firestore.FieldValue.increment(1)
    }, { merge: true });

    // 4) Redirect back to thread
    res.redirect(`/poke/${id}`);
  } catch (err) {
    console.error('❌ Failed to post comment:', err);
    res.status(500).send("Failed to post comment");
  }
});

// --- User Profile Page ---
app.get('/user/:username', async (req, res) => {
  const { username } = req.params;
  const currentUser = req.session.user?.username;

  try {
    const userDoc = await db.collection('users').doc(username).get();
    if (!userDoc.exists) return res.status(404).send("User not found");

    const userData = userDoc.data();
    const followersUsernames = userData.followers || [];
    const followingUsernames = userData.following || [];
    const isFollowing = currentUser ? followersUsernames.includes(currentUser) : false;

    let requestSent = false;
    if (currentUser && currentUser !== username) {
      const reqSnap = await db
        .collection('users')
        .doc(username)
        .collection('followRequests')
        .doc(currentUser)
        .get();
      requestSent = reqSnap.exists;
    }

    const profilePic = userData.profile_pic || '/default-avatar.png';
    const page = parseInt(req.query.page) || 1;
    const commentsPerPage = 10;

    // ✅ Fetch user's comments
    const commentsSnap = await db.collection('comments')
      .where('user', '==', username)
      .orderBy('timestamp', 'desc')
      .limit(commentsPerPage)
      .get();

    const comments = commentsSnap.docs.map(doc => {
      const data = doc.data();
      return {
        ...data,
        relativeTime: data.timestamp ? dayjs(data.timestamp.toDate()).fromNow() : ''
      };
    });

    const totalComments = comments.length;
    const totalLikes = comments.reduce((sum, c) => sum + (c.like_reactions || 0), 0);

    const followersCount = followersUsernames.length;
    const followingCount = followingUsernames.length;

    // ✅ Get logged-in user's following list (for follow-back logic)
    let currentUserFollowing = [];
    if (currentUser) {
      const currUserDoc = await db.collection('users').doc(currentUser).get();
      currentUserFollowing = currUserDoc.data()?.following || [];
    }

    // ✅ Enrich followers with profilePic and follow-back flag
    const followers = await Promise.all(
      followersUsernames.map(async followerUsername => {
        const uDoc = await db.collection('users').doc(followerUsername).get();
        const uData = uDoc.data();
        return {
          username: followerUsername,
          profilePic: uData?.profile_pic || '/default-avatar.png',
          showFollowBack: currentUser &&
                          currentUser !== followerUsername &&
                          !currentUserFollowing.includes(followerUsername)
        };
      })
    );

    // ✅ Enrich following with profilePic
    const following = await Promise.all(
      followingUsernames.map(async followeeUsername => {
        const uDoc = await db.collection('users').doc(followeeUsername).get();
        const uData = uDoc.data();
        return {
          username: followeeUsername,
          profilePic: uData?.profile_pic || '/default-avatar.png'
        };
      })
    );

    // ✅ Fetch the user’s own Fevers
    const feversSnap = await db
     .collection('fevers')
    .where('user', '==', username)
     .orderBy('createdAt', 'desc')
     .get();
    const fevers = feversSnap.docs.map(doc => {
      const d = doc.data();
      return {
       id: doc.id,
       mediaURL: d.mediaURL,
       mediaType: d.mediaType,
       createdAt: d.createdAt.toDate().toISOString()
     };
    });

    // ✅ Get incoming follow requests if viewing own profile
    let followRequests = [];
    if (currentUser === username) {
      const followReqSnap = await db.collection('users')
        .doc(username)
        .collection('followRequests')
        .get();

      followRequests = followReqSnap.docs.map(doc => doc.id);
    }

    // ✅ Final render
    res.render('user', {
      profileUser: username,
      profilePic,
      comments,
      totalComments,
      totalLikes,
      followersCount,
      followingCount,
      isFollowing,
      followRequests,
      requestSent,
      followers,
      following,
      fevers
    });

  } catch (err) {
    console.error('User profile error:', err);
    res.status(500).send("Failed to load profile");
  }
});

// Accept follow
app.post('/user/:fromUser/accept-follow', async (req, res) => {
  const toUser = req.session.user?.username;
  const fromUser = req.params.fromUser;

  if (!toUser) return res.redirect('/?error=Login required');

  try {
    const userRef = db.collection('users').doc(toUser);

    // Add follower
    await userRef.update({
      followers: admin.firestore.FieldValue.arrayUnion(fromUser)
    });

    // Add to following list of sender
    await db.collection('users').doc(fromUser).update({
      following: admin.firestore.FieldValue.arrayUnion(toUser)
    });

    // Remove the follow request
    await userRef.collection('followRequests').doc(fromUser).delete();

    res.redirect(`/user/${toUser}`);
  } catch (err) {
    console.error('Accept follow error:', err);
    res.status(500).send('Failed to accept follow request');
  }
});

// Reject follow
app.post('/user/:fromUser/reject-follow', async (req, res) => {
  const toUser = req.session.user?.username;
  const fromUser = req.params.fromUser;

  if (!toUser) return res.redirect('/?error=Login required');

  try {
    await db.collection('users').doc(toUser)
      .collection('followRequests').doc(fromUser).delete();

    res.redirect(`/user/${toUser}`);
  } catch (err) {
    console.error('Reject follow error:', err);
    res.status(500).send('Failed to reject follow request');
  }
});

// ✅ Inbox Hub Page: /inbox
app.get('/inbox', async (req, res) => {
  if (!req.session.user) return res.redirect('/?error=Login required');

  // Only “mentions” badges now
  const username = req.session.user.username;
 try {
    const tagSnap = await db.collection('tags')
      .where('taggedUserId', '==', username)
      .where('seen', '==', false)
      .get();
    const tagNotifications = tagSnap.size;
    res.render('inbox', {
      user: {
        ...req.session.user,
        tagNotifications,
        unreadCount: tagNotifications
      }
    });
  } catch (err) {
    console.error('❌ Inbox error:', err);
    res.status(500).send("Inbox error");
  }
});

// 🔔 Inbox Tags Page: /inbox/tags
app.get('/inbox/tags', async (req, res) => {
  if (!req.session.user) return res.redirect('/?error=Login required');

  try {
    const username = req.session.user.username;
    const tagSnap = await db.collection('tags')
      .where('taggedUserId', '==', username)
      .orderBy('timestamp', 'desc')
      .get();

    const taggedComments = tagSnap.docs.map(doc => {
      const tag = doc.data();
      return {
        fromUser:      tag.fromUser,
        content:       tag.content,
        threadType:    tag.threadType || 'team',
        link:          tag.link || '#',
        seen:          tag.seen || false
      };
    });

    // mark all as seen
    const batch = db.batch();
    tagSnap.docs.forEach(doc => {
      if (!doc.data().seen) batch.update(doc.ref, { seen: true });
    });
    await batch.commit();

    // Render, passing teamToLeagueMap for the template
    res.render('inbox-tags', {
      user: req.session.user,
      taggedComments,
      teamToLeagueMap,      // <<-- add this line
      headerClass: 'header-home',
      useTeamHeader: false
    });
  } catch (err) {
    console.error('❌ Tag inbox error:', err);
    res.status(500).send("Inbox tags error");
  }
});

// --- Follow a user ---
app.post('/user/:username/follow', async (req, res) => {
  const currentUser = req.session.user?.username;
  const targetUser = req.params.username;

  if (!currentUser || currentUser === targetUser) {
    return res.redirect('/user/' + targetUser);
  }

  try {
    const targetDoc = await db.collection('users').doc(targetUser).get();
    const targetData = targetDoc.data();

    // ✅ Always use request-based flow for now
    await db.collection('users').doc(targetUser)
      .collection('followRequests')
      .doc(currentUser)
      .set({ requestedAt: admin.firestore.FieldValue.serverTimestamp() });

    res.redirect('/user/' + targetUser);
  } catch (err) {
    console.error('❌ Follow request error:', err);
    res.redirect('/user/' + targetUser);
  }
});

// --- Unfollow a user ---
app.post('/user/:username/unfollow', async (req, res) => {
  const currentUser = req.session.user?.username;
  const targetUser = req.params.username;

  if (!currentUser || currentUser === targetUser) {
    return res.redirect('/user/' + targetUser);
  }

  try {
    await db.collection('users').doc(currentUser).update({
      following: admin.firestore.FieldValue.arrayRemove(targetUser)
    });

    await db.collection('users').doc(targetUser).update({
      followers: admin.firestore.FieldValue.arrayRemove(currentUser)
    });

    res.redirect('/user/' + targetUser);
  } catch (err) {
    console.error('❌ Unfollow error:', err);
    res.redirect('/user/' + targetUser);
  }
});
// --- Upload/change profile picture ---
app.post('/user/upload-avatar', upload.single('profile_pic'), async (req, res) => {
  const username = req.session.user?.username;
  if (!username || !req.file) return res.redirect('/');

  const filePath = `/uploads/${req.file.filename}`;

  try {
    await db.collection('users').doc(username).update({
      profile_pic: filePath
    });

    req.session.user.profile_pic = filePath; // update session (optional)
    res.redirect('/user/' + username);
  } catch (err) {
    console.error('❌ Avatar upload error:', err);
    res.redirect('/user/' + username);
  }
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
