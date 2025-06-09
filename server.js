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
const sanitizeHtml = require('sanitize-html');
const rateLimit = require('express-rate-limit');

// Rate limiter for story uploads (5 per minute per IP)
const storyLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5,              // max 5 uploads/comments per minute
  message: 'Too many uploads, please slow down.'
});

const teamImages = {
  'la-liga': {
    'real-madrid': '/la-liga-images/real-madrid.png',
    'barcelona': '/la-liga-images/barcelona.png',
    'atletico-madrid': '/la-liga-images/atletico.png',
    'athletic-bilbao': '/la-liga-images/athletic-bilbao.png',
    'sevilla': '/la-liga-images/sevilla.png',
    'real-sociedad': '/la-liga-images/real-sociedad.png',
    'valencia': '/la-liga-images/valencia.png',
    'villarreal': '/la-liga-images/villarreal.png',
    'real-betis': '/la-liga-images/real-betis.png',
    'celta-vigo': '/la-liga-images/celta-vigo.png',
    'getafe': '/la-liga-images/getafe.png',
    'osasuna': '/la-liga-images/osasuna.png',
    'real-mallorca': '/la-liga-images/real-mallorca.png',
    'rayo-vallecano': '/la-liga-images/rayo-vallecano.png',
    'espanyol': '/la-liga-images/rcd-espanyol.png',
    'girona': '/la-liga-images/girona.png',
    'alaves': '/la-liga-images/deportivo-alaves.png',
    'las-palmas': '/la-liga-images/las-palmas.png',
    'leganes': '/la-liga-images/cd-leganes.png',
    'real-valladolid': '/la-liga-images/real-valladolid.png',
  },
  'bundesliga': {
    'bayern-munich': '/bundesliga-images/bayern-munich.jpg',
    'borussia-dortmund': '/bundesliga-images/borussia-dortmund.jpg',
    'bayer-leverkusen': '/bundesliga-images/bayer-leverkusen.jpg',
    'rb-leipzig': '/bundesliga-images/rb-leipzig.jpg',
    'eintracht-frankfurt': '/bundesliga-images/eintracht-frankfurt.jpg',
    'borussia-monchengladbach': '/bundesliga-images/borussia-monchengladbach.jpg',
    'union-berlin': '/bundesliga-images/union-berlin.jpg',
    'vfl-wolfsburg': '/bundesliga-images/vfl-wolfsburg.jpg',
    'freiburg': '/bundesliga-images/freiburg.jpg',
    'mainz': '/bundesliga-images/mainz.jpg',
    'augsburg': '/bundesliga-images/augsburg.jpg',
    'hoffenheim': '/bundesliga-images/hoffenheim.jpg',
    'vfl-bochum': '/bundesliga-images/vfl-bochum.jpg',
    'stuttgart': '/bundesliga-images/stuttgart.jpg',
    'heidenheim': '/bundesliga-images/heidenheim.jpg',
    'st-pauli': '/bundesliga-images/st-pauli.jpg',
    'werder-bremen': '/bundesliga-images/werder-bremen.jpg',
    'holstein': '/bundesliga-images/holstein.jpg',
  },
  'eredivisie': {
    'ajax': '/eredivisie-images/ajax.jpg',
    'psv-eindhoven': '/eredivisie-images/psv-eindhoven.jpg',
    'feyenoord': '/eredivisie-images/feyenoord.jpg',
    'az-alkmaar': '/eredivisie-images/az-alkmaar.jpg',
    'fc-twente': '/eredivisie-images/fc-twente.jpg',
    'fc-utrecht': '/eredivisie-images/fc-utrecht.jpg',
    'sc-heerenveen': '/eredivisie-images/sc-heerenveen.jpg',
    'nec-nijmegen': '/eredivisie-images/nec-nijmegen.jpg',
    'sparta-rotterdam': '/eredivisie-images/sparta-rotterdam.jpg',
    'go-ahead-eagles': '/eredivisie-images/go-ahead-eagles.jpg',
    'fc-groningen': '/eredivisie-images/fc-groningen.jpg',
    'pec-zwolle': '/eredivisie-images/pec-zwolle.jpg',
    'fortuna-sittard': '/eredivisie-images/fortuna-sittard.jpg',
    'nac-breda': '/eredivisie-images/nac-breda.jpg',
    'heracles-almelo': '/eredivisie-images/heracles-almelo.jpg',
    'willem-ii': '/eredivisie-images/willem-ii.jpg',
    'almere-city': '/eredivisie-images/almere-city.jpg',
    'rkc-waalwijk': '/eredivisie-images/rkc-waalwijk.jpg',
  },
  'liga-portugal': {
    'sporting-cp': '/liga-portugal-images/sporting-cp.png',
    'sl-benfica': '/liga-portugal-images/sl-benfica.png',
    'fc-porto': '/liga-portugal-images/fc-porto.png',
    'sc-braga': '/liga-portugal-images/sc-braga.png',
    'vitoria-guimaraes': '/liga-portugal-images/vitoria-guimaraes.png',
    'cd-santa-clara': '/liga-portugal-images/cd-santa-clara.png',
    'fc-famalicao': '/liga-portugal-images/fc-famalicao.png',
    'casa-pia': '/liga-portugal-images/casa-pia.png',
    'gd-estoril-praia': '/liga-portugal-images/gd-estoril-praia.png',
    'rio-ave': '/liga-portugal-images/rio-ave.png',
    'moreirense': '/liga-portugal-images/moreirense.png',
    'cd-nacional': '/liga-portugal-images/cd-nacional.png',
    'gil-vicente': '/liga-portugal-images/gil-vicente.png',
    'fc-arouca': '/liga-portugal-images/fc-arouca.png',
    'sc-farense': '/liga-portugal-images/sc-farense.png',
    'cf-estrela-amadora': '/liga-portugal-images/cf-estrela-amadora.png',
    'boavista': '/liga-portugal-images/boavista.png',
    'afs': '/liga-portugal-images/afs.png',
  },
  'ligue-1': {
    'psg': '/ligue1-images/psg.jpg',
    'olympique-marseille': '/ligue1-images/olympique-marseille.jpg',
    'monaco': '/ligue1-images/monaco.jpg',
    'lyon': '/ligue1-images/lyon.jpg',
    'lille': '/ligue1-images/lille.jpg',
    'nice': '/ligue1-images/nice.jpg',
    'rennes': '/ligue1-images/rennes.jpg',
    'lens': '/ligue1-images/lens.jpg',
    'strasbourg': '/ligue1-images/strasbourg.jpg',
    'reims': '/ligue1-images/reims.jpg',
    'brest': '/ligue1-images/brest.jpg',
    'toulouse': '/ligue1-images/toulouse.jpg',
    'montpellier': '/ligue1-images/montpellier.jpg',
    'nantes': '/ligue1-images/nantes.jpg',
    'le-havre': '/ligue1-images/le-havre.jpg',
    'auxerre': '/ligue1-images/auxerre.jpg',
    'angers': '/ligue1-images/angers.jpg',
    'saint-etienne': '/ligue1-images/saint-etienne.jpg',
  },
  'premier-league': {
    'manchester-united': '/premier-images/man-united.png',
    'liverpool': '/premier-images/liverpool.png',
    'manchester-city': '/premier-images/man-city.png',
    'arsenal': '/premier-images/arsenal.png',
    'chelsea': '/premier-images/chelsea.png',
    'tottenham': '/premier-images/tottenham.png',
    'newcastle': '/premier-images/newcastle.png',
    'aston-villa': '/premier-images/aston-villa.png',
    'west-ham': '/premier-images/west-ham.png',
    'brighton': '/premier-images/brighton.png',
    'brentford': '/premier-images/brentford.png',
    'wolves': '/premier-images/wolves.png',
    'everton': '/premier-images/everton.png',
    'crystal-palace': '/premier-images/crystal-palace.png',
    'fulham': '/premier-images/fulham.png',
    'bournemouth': '/premier-images/bournemouth.png',
    'leicester-city': '/premier-images/leicester-city.png',
    'nottingham-forest': '/premier-images/nottingham-forest.png',
    'ipswich-town': '/premier-images/ipswich-town.png',
    'southampton': '/premier-images/southampton.png',
  },
  'roshn-saudi-league': {
    'al-hilal': '/roshn-saudi-images/al-hilal.png',
    'al-nassr': '/roshn-saudi-images/al-nassr.png',
    'al-ittihad': '/roshn-saudi-images/al-ittihad.png',
    'al-ahli': '/roshn-saudi-images/al-ahli.png',
    'al-shabab': '/roshn-saudi-images/al-shabab.png',
    'al-taawoun': '/roshn-saudi-images/al-taawoun.png',
    'al-ettifaq': '/roshn-saudi-images/al-ettifaq.png',
    'al-fateh': '/roshn-saudi-images/al-fateh.png',
    'al-fayha': '/roshn-saudi-images/al-fayha.png',
    'damac': '/roshn-saudi-images/damac.png',
    'al-wehda': '/roshn-saudi-images/al-wehda.png',
    'al-raed': '/roshn-saudi-images/al-raed.png',
    'al-khaleej': '/roshn-saudi-images/al-khaleej.png',
    'al-riyadh': '/roshn-saudi-images/al-riyadh.png',
    'al-okhdood': '/roshn-saudi-images/al-okhdood.png',
    'al-qadsiah': '/roshn-saudi-images/al-qadsiah.png',
    'al-kholood': '/roshn-saudi-images/al-kholood.png',
    'al-orobah': '/roshn-saudi-images/al-orobah.png',
  },
  'serie-a': {
    'inter-milan': '/serie-a-images/inter-milan.png',
    'juventus': '/serie-a-images/juventus.png',
    'ac-milan': '/serie-a-images/ac-milan.png',
    'napoli': '/serie-a-images/napoli.png',
    'roma': '/serie-a-images/roma.png',
    'fiorentina': '/serie-a-images/fiorentina.png',
    'atalanta': '/serie-a-images/atalanta.png',
    'lazio': '/serie-a-images/lazio.png',
    'bologna': '/serie-a-images/bologna.png',
    'como': '/serie-a-images/como.png',
    'torino': '/serie-a-images/torino.png',
    'udinese': '/serie-a-images/udinese.png',
    'genoa': '/serie-a-images/genoa.png',
    'cagliari': '/serie-a-images/cagliari.png',
    'verona': '/serie-a-images/verona.png',
    'parma': '/serie-a-images/parma.png',
    'lecce': '/serie-a-images/lecce.png',
    'venezia': '/serie-a-images/venezia.png',
    'empoli': '/serie-a-images/empoli.png',
    'monza': '/serie-a-images/monza.png',
  },
  'super-lig': {
    'galatasaray': '/super-lig-images/galatasaray.png',
    'fenerbahce': '/super-lig-images/fenerbahce.png',
    'besiktas': '/super-lig-images/besiktas.png',
    'trabzonspor': '/super-lig-images/trabzonspor.png',
    'istanbul-basaksehir': '/super-lig-images/istanbul-basaksehir.png',
    'kasimpasa': '/super-lig-images/kasimpasa.png',
    'eyupspor': '/super-lig-images/eyupspor.png',
    'goztepe': '/super-lig-images/goztepe.png',
    'bodrum-fk': '/super-lig-images/bodrum-fk.png',
    'samsunspor': '/super-lig-images/samsunspor.png',
    'konyaspor': '/super-lig-images/konyaspor.png',
    'antalyaspor': '/super-lig-images/antalyaspor.png',
    'sivasspor': '/super-lig-images/sivasspor.png',
    'alanyaspor': '/super-lig-images/alanyaspor.png',
    'caykur-rizespor': '/super-lig-images/caykur-rizespor.png',
    'gaziantep-fk': '/super-lig-images/gaziantep-fk.png',
    'kayserispor': '/super-lig-images/kayserispor.png',
    'hatayspor': '/super-lig-images/hatayspor.png',
    'adana-demirspor': '/super-lig-images/adana-demirspor.png',
  },
};

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

// --- 🔐 Login Check Middleware ---
function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/?error=Login required to view stories');
  }
  next();
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

// Multi-field upload for comments, profiles, tactical images
const multiUpload = upload.fields([
  { name: 'media', maxCount: 1 },
  { name: 'profile_pic', maxCount: 1 },
  { name: 'tacticImage', maxCount: 1 } // ✅ for tactical board
]);

// ✅ First middleware: fetch unread messages
app.use(async (req, res, next) => {
  try {
    if (req.session.user?.username) {
      const username = req.session.user.username;

      // Count unread messages
      const msgSnap = await db.collection('messages')
        .where('receiver', '==', username)
        .where('seenByReceiver', '==', false)
        .get();
      req.session.user.unreadCount = msgSnap.size;

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
  res.locals.hideAuthModals = false; // ✅ This line fixes your current issue
  next();
});

async function loadHomeData() {
  const cutoff = dayjs().subtract(24, 'hour').toDate();

  const statsSnap = await db.collection('userStats')
    .orderBy('score', 'desc')
    .limit(5)
    .get();

  const topFans = statsSnap.docs.map(doc => {
    const data = doc.data();
    return {
      username: doc.id,
      comments: data.comments || 0,
      likes: (data.likes || 0) + (data.funny || 0) + (data.angry || 0) + (data.love || 0)
    };
  });

  const storiesSnap = await db.collection('stories')
    .where('createdAt', '>=', cutoff)
    .orderBy('createdAt', 'desc')
    .get();

  const storyDocs = storiesSnap.docs;

  const commentPromises = storyDocs.map(doc =>
    db.collection('stories').doc(doc.id).collection('comments').get()
  );
  const reactionPromises = storyDocs.map(doc =>
    db.collection('stories').doc(doc.id).collection('reactions').get()
  );

  const [commentSnaps, reactionSnaps] = await Promise.all([
    Promise.all(commentPromises),
    Promise.all(reactionPromises)
  ]);

  const stories = storyDocs.map((doc, i) => {
    const story = doc.data();
    const reactions = {};
    reactionSnaps[i].forEach(r => {
      const { reaction_type } = r.data();
      reactions[reaction_type] = (reactions[reaction_type] || 0) + 1;
    });

    return {
      _id: doc.id,
      ...story,
      relativeTime: dayjs(story.createdAt.toDate()).fromNow(),
      comments: commentSnaps[i].docs.map(c => c.data()),
      reactions: Object.entries(reactions).map(([type, count]) => ({ type, count }))
    };
  });

  const battleSnap = await db.collection('battles')
    .orderBy('created_at', 'desc')
    .limit(1)
    .get();

  const battle = battleSnap.empty ? null : { id: battleSnap.docs[0].id, ...battleSnap.docs[0].data() };

  return { stories, topFans, battle };
}

// --- Reusable Homepage Error Renderer ---
async function renderHomeWithError(res, errorType, errorMsg) {
  try {
    const { stories, topFans, battle } = await loadHomeData();

    const data = {
      stories,
      topFans,
      battle,
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
    const { stories, topFans, battle } = await loadHomeData();

    let user = req.session.user || null;

    if (user) {
      const username = user.username;

      const [chatSnap, tagSnap, storySnap] = await Promise.all([
        db.collection('messages')
          .where('receiver', '==', username)
          .where('seenByReceiver', '==', false)
          .get(),
        db.collection('tags')
          .where('taggedUserId', '==', username)
          .where('seen', '==', false)
          .get(),
        db.collection('users')
          .doc(username)
          .collection('storyNotifications')
          .get()
      ]);

      user = {
        ...user,
        chatNotifications: chatSnap.size,
        tagNotifications: tagSnap.size,
        storyNotifications: storySnap.size,
        unreadCount: chatSnap.size + tagSnap.size + storySnap.size
      };
    }

    res.render('index', {
      user,
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
app.get('/story/:id', requireLogin, async (req, res) => {
  const { id } = req.params;

  // Optionally: validate ID format
  if (!id) return res.redirect('/');

  // Redirect to homepage with ?story=ID (handled client-side)
  res.redirect(`/?story=${id}`);
});

app.post('/stories/upload', storyLimiter, upload.single('storyMedia'), async (req, res) => {
  console.log('📦 req.file =', req.file);
  if (!req.session.user) return res.redirect('/?error=Login required');
  if (!req.file) return res.redirect('/?error=No file uploaded');

  const filePath = `/uploads/${req.file.filename}`;
  const username = req.session.user.username;

  // Sanitize caption to prevent XSS
  const caption = sanitizeHtml(req.body.caption || '', {
    allowedTags: [],
    allowedAttributes: {}
  });

  try {
    const storyRef = await db.collection('stories').add({
      image: filePath,
      username,
      caption,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    await storyRef.update({ _id: storyRef.id }); // Save the Firestore doc ID

    res.redirect('/');
  } catch (err) {
    console.error('❌ Error uploading story:', err);
    res.redirect('/?error=Failed to save story');
  }
});

// --- React to a story ---
app.post('/stories/:id/react', requireLogin, async (req, res) => {
  const { id } = req.params;
  const { reaction_type } = req.body;
  const username = req.session.user.username;

  try {
    console.log('📌 Reaction:', { id, reaction_type, username });

    const reactionRef = db.collection('stories').doc(id)
      .collection('reactions').doc(username); // Unique doc per user

    await reactionRef.set({ reaction_type, user: username }, { merge: true });

    // Notify the story owner
    const storyDoc = await db.collection('stories').doc(id).get();
    const to = storyDoc.data()?.username;

    if (to && to !== username) {
      const notifRef = db.collection('users').doc(to).collection('storyNotifications');
      
      // Only send notification if one doesn’t already exist for this reaction
      const existingSnap = await notifRef
        .where('from', '==', username)
        .where('storyId', '==', id)
        .where('type', '==', 'reaction')
        .limit(1)
        .get();

      if (existingSnap.empty) {
        await notifRef.add({
          from: username,
          storyId: id,
          type: 'reaction',
          timestamp: admin.firestore.FieldValue.serverTimestamp()
        });
      }
    }

    res.json({ success: true });
  } catch (err) {
    console.error('❌ Story reaction error:', err);
    res.status(500).json({ success: false });
  }
});

// --- Comment on a story ---
app.post('/stories/:id/comment', requireLogin, async (req, res) => {
  console.log('Incoming comment body:', req.body);
  if (!req.session.user) return res.status(401).json({ success: false });

  const { id } = req.params;
  const { comment } = req.body;
  const username = req.session.user.username;

  if (!comment?.trim()) return res.status(400).json({ success: false });

  try {
    console.log('💬 Story comment:', { id, comment, user: username });

    await db.collection('stories').doc(id)
  .collection('comments')
  .add({
    user: username,
    comment: comment.trim(),
    timestamp: admin.firestore.FieldValue.serverTimestamp()
  });

    // Optional: send notification
    const storyDoc = await db.collection('stories').doc(id).get();
    const to = storyDoc.data()?.username;
    if (to && to !== username) {
      await db.collection('users').doc(to).collection('storyNotifications').add({
        from: username,
        storyId: id,
        type: 'reply',
        timestamp: admin.firestore.FieldValue.serverTimestamp()
      });
    }

    res.json({ success: true });
  } catch (err) {
    console.error('❌ Story comment error:', err);
    res.status(500).json({ success: false });
  }
});

// --- Story Notifications Inbox ---
app.get('/inbox/stories', requireLogin, async (req, res) => {
  const currentUser = req.session.user?.username;
  if (!currentUser) return res.redirect('/login');

  try {
    const snap = await db.collection('users')
      .doc(currentUser)
      .collection('storyNotifications')
      .orderBy('timestamp', 'desc')
      .get();

    const storyNotifications = snap.docs.map(doc => doc.data());

    res.render('inbox-stories', { storyNotifications });
  } catch (err) {
    console.error('❌ Story inbox error:', err);
    res.status(500).send('Error loading story notifications');
  }
});

// --- Notify when someone views a story ---
app.post('/notify-story-view', requireLogin, async (req, res) => {
  const { to, from, storyId } = req.body;

  if (!to || !from || !storyId || to === from) {
    return res.status(400).send('Invalid notification data');
  }

  try {
    const notifRef = db.collection('users')
      .doc(to)
      .collection('storyNotifications');

    const existingSnap = await notifRef
      .where('from', '==', from)
      .where('storyId', '==', storyId)
      .limit(1)
      .get();

    if (!existingSnap.empty) return res.status(200).send('Already notified');

    await notifRef.add({
      from,
      storyId,
      timestamp: admin.firestore.FieldValue.serverTimestamp()
    });

    res.status(200).send('Notification sent');
  } catch (err) {
    console.error('🔥 Firestore error in notify-story-view:', err);
    res.status(500).send('Error sending notification');
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

    // ✅ Save the poke thread
    const newDocRef = await db.collection('rivalPokes').add({
  teamA,
  teamB,
  createdBy: username,
  text: text.trim(),
  media,
  createdAt: admin.firestore.FieldValue.serverTimestamp(),
  score: {
    teamA: 0,
    teamB: 0
  }
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

    // Fetch comments for the team
    const commentsRef = db.collection('comments')
      .where('team', '==', teamname)
      .orderBy('timestamp', 'desc');

    const snapshot = await commentsRef.get();
    const allDocs = snapshot.docs;

    const page = parseInt(req.query.page) || 1;
    const limit = 40;
    const offset = (page - 1) * limit;

    const paginatedDocs = allDocs.slice(offset, offset + limit);
    const comments = paginatedDocs.map(doc => {
      const data = doc.data();
      return {
        id: doc.id,
        ...data,
        relativeTime: data.timestamp ? dayjs(data.timestamp.toDate()).fromNow() : ''
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

const fourHoursAgo = new Date(Date.now() - 4 * 60 * 60 * 1000); // 4 hours ago

const pokeThreads = allPokes
  .filter(doc => {
    const data = doc.data();
    return data.createdAt?.toDate?.() > fourHoursAgo;
  })
  .sort((a, b) => b.data().createdAt.toMillis() - a.data().createdAt.toMillis())
  .slice(0, 3)
  .map(doc => {
    const data = doc.data();
    return {
      id: doc.id,
      ...data,
      relativeTime: data.createdAt ? dayjs(data.createdAt.toDate()).fromNow() : '',
      createdAtMillis: data.createdAt?.toMillis?.() || 0 // needed for countdown
    };
  });

    const teamDoc = await db.collection('teams').doc(teamname).get();
    const teamData = teamDoc.exists ? teamDoc.data() : null;

    const relativeTimes = comments.map(comment => {
      const timestamp = comment.timestamp?.toDate?.();
      if (!timestamp) return 'Just now';

      const now = new Date();
      const secondsAgo = Math.floor((now - timestamp) / 1000);

      if (secondsAgo < 60) return `${secondsAgo}s ago`;
      const minutesAgo = Math.floor(secondsAgo / 60);
      if (minutesAgo < 60) return `${minutesAgo}m ago`;
      const hoursAgo = Math.floor(minutesAgo / 60);
      if (hoursAgo < 24) return `${hoursAgo}h ago`;
      const daysAgo = Math.floor(hoursAgo / 24);
      return `${daysAgo}d ago`;
    });

    res.render('team', {
  user: req.session.user || null,
  teamname,
  teamData,
  comments,
  currentPage: page,
  totalPages,
  relativeTimes,
  pokeThreads,
  leagueSlug,
  leagueName,
  useTeamHeader: true,
  imagePath,
  teamToLeagueMap, // ✅ THIS FIXES THE CRASH
  pokeError: 'A reverse rivalry is already active. Please wait until it expires.'
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

// 💬 Post a comment in a Rival Poke thread
app.post('/poke/:id/comment', multiUpload, async (req, res) => {
  const { id } = req.params;
  const { text } = req.body;
  const username = req.session.user?.username;

  if (!username || !text?.trim()) return res.status(400).send("Missing data");

  const media =
    req.files?.media?.[0]?.path?.includes('uploads')
      ? `/uploads/${req.files.media[0].filename}`
      : '';

  const mentionRegex = /@([a-zA-Z0-9_]+)/g;
  const mentions = [...text.matchAll(mentionRegex)].map(m => m[1]);

  try {
    // Get poke data for fan side
    const pokeDoc = await db.collection('rivalPokes').doc(id).get();
    const pokeData = pokeDoc.data();

    const fanSide = (username === pokeData.createdBy) ? 'teamA' : 'teamB';

    // Save comment
    await db.collection('rivalPokes').doc(id).collection('comments').add({
      user: username,
      text: text.trim(),
      media,
      timestamp: admin.firestore.FieldValue.serverTimestamp(),
      team: fanSide
    });
    await db.collection('userStats').doc(username).set({
  comments: admin.firestore.FieldValue.increment(1),
  likes: 0,
  funny: 0,
  angry: 0,
  love: 0,
  score: admin.firestore.FieldValue.increment(1)
}, { merge: true });

    // Loop through mentions
    for (const mentionedUsername of mentions) {
      const userSnapshot = await db.collection('users')
        .where('username', '==', mentionedUsername)
        .limit(1)
        .get();

      if (!userSnapshot.empty) {
        const mentionedUserDoc = userSnapshot.docs[0];
        const mentionedUserId = mentionedUserDoc.id;

        // ✅ Store in notifications (for your real-time socket stuff)
        await db.collection('notifications').add({
          toUser: mentionedUserId,
          fromUser: username,
          type: 'mention',
          text,
          link: `/poke/${id}`,
          timestamp: new Date(),
          read: false
        });

        // ✅ Store in tags (for inbox-tags.ejs)
        await db.collection('tags').add({
          fromUser: username,
          taggedUserId: mentionedUsername,
          content: text,
          threadType: 'poke',
          link: `/poke/${id}#comments`,
          timestamp: new Date(),
          seen: false
        });

        // ✅ Emit via socket.io if user is online
        if (io && io.to) {
          io.to(mentionedUserId).emit('newMention', {
            fromUser: username,
            text,
            link: `/poke/${id}`
          });
        }
      }
    }

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

    // ✅ Fetch user's stories
    const storiesSnap = await db.collection('stories')
      .where('username', '==', username)
      .orderBy('createdAt', 'desc')
      .get();

    const stories = storiesSnap.docs.map(doc => {
      const data = doc.data();
      return {
        ...data,
        relativeTime: data.createdAt ? dayjs(data.createdAt.toDate()).fromNow() : ''
      };
    });

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
      stories,
      totalComments,
      totalLikes,
      followersCount,
      followingCount,
      isFollowing,
      followRequests,
      requestSent,
      followers,
      following
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

  const username = req.session.user.username;
  const currentUser = req.session.user;

  try {
    // 🔴 Unseen chat messages
    const chatSnap = await db.collection('messages')
      .where('receiver', '==', username)
      .where('seenByReceiver', '==', false)
      .get();
    const chatNotifications = chatSnap.size;

    // 🏷️ Unseen mentions (tags)
    const tagSnap = await db.collection('tags')
      .where('taggedUserId', '==', username)
      .where('seen', '==', false)
      .get();
    const tagNotifications = tagSnap.size;

    // 📸 Unseen story notifications
    const storySnap = await db.collection('users')
      .doc(username)
      .collection('storyNotifications')
      .get();
    const storyNotifications = storySnap.size;

    // 📦 Total inbox red badge count
    const inboxTotalNotifications = chatNotifications + tagNotifications + storyNotifications;

    // 🧠 Inject notifications into user object for header rendering
    res.render('inbox', {
      user: {
        ...req.session.user,
        chatNotifications,
        tagNotifications,
        storyNotifications,
        inboxTotalNotifications,
        unreadCount: chatNotifications // used in header
      },
      currentUser
    });
  } catch (err) {
    console.error('❌ Inbox error:', err);
    res.status(500).send("Inbox error");
  }
});

// ✅ Inbox Chat Page: /inbox/chat
app.get('/inbox/chat', async (req, res) => {
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

      if (
        !conversations[otherUser] ||
        new Date(msg.timestamp).getTime() > conversations[otherUser].timestamp.getTime()
      ) {
        conversations[otherUser] = {
          user: otherUser,
          lastMessage: msg.content,
          timestamp: new Date(msg.timestamp),
          seenByReceiver: msg.seenByReceiver || false,
          profile_pic: msg.sender === username ? msg.receiverPic : msg.senderPic
        };
      }
    });

    const sorted = Object.values(conversations).sort((a, b) => b.timestamp - a.timestamp);

    const unseen = await db.collection('messages')
      .where('receiver', '==', username)
      .where('seenByReceiver', '==', false)
      .get();

    await Promise.all(unseen.docs.map(doc => doc.ref.update({ seenByReceiver: true })));

    res.render('inbox-chat', {
      conversations: sorted,
      currentUser,
      messages: [],
      otherUser: null
    });
  } catch (err) {
    console.error('❌ Inbox Chat error:', err);
    res.status(500).send("Inbox chat error");
  }
});

// ✅ Inbox Tags Page: /inbox/tags
app.get('/inbox/tags', async (req, res) => {
  if (!req.session.user) return res.redirect('/?error=Login required');

  try {
    const tagSnap = await db.collection('tags')
      .where('taggedUserId', '==', req.session.user.username)
      .orderBy('timestamp', 'desc')
      .get();

    const taggedComments = tagSnap.docs.map(doc => {
      const tag = doc.data();
      return {
        fromUser: tag.fromUser,
        content: tag.content,
        threadType: tag.threadType || 'team',
        link: tag.link || '#',
        seen: tag.seen || false
      };
    });

    const batch = db.batch();
    tagSnap.forEach(doc => {
      if (!doc.data().seen) batch.update(doc.ref, { seen: true });
    });
    await batch.commit();

    res.render('inbox-tags', {
      taggedComments,
      headerClass: 'header-home',
      showAuthLinks: true,
      showLeagueLink: false,
      useTeamHeader: false,
      hideAuthModals: false,
      currentUser: req.session.user
    });
  } catch (err) {
    console.error('❌ Tag inbox error:', err);
    res.status(500).send("Inbox tags error");
  }
});

// ✅ Individual Chat Page: /chat/:username
app.get('/chat/:username', async (req, res) => {
  if (!req.session.user) return res.redirect('/?error=Login required');

  const currentUser = req.session.user;
  const username = currentUser.username;
  const otherUser = req.params.username;

  try {
    const convoRef = db.collection('messages')
      .where('participants', 'array-contains-any', [username, otherUser])
      .orderBy('timestamp', 'asc');

    const snapshot = await convoRef.get();
    const participantsSorted = [username, otherUser].sort().join(',');

    const messages = [];
    snapshot.forEach(doc => {
      const data = doc.data();
      const dataSorted = data.participants.sort().join(',');
      if (dataSorted === participantsSorted) {
        messages.push({ id: doc.id, ...data });
      }
    });

    const convoSnapshot = await db.collection('messages')
      .where('participants', 'array-contains', username)
      .orderBy('timestamp', 'desc')
      .get();

    const conversations = {};
    convoSnapshot.forEach(doc => {
      const msg = doc.data();
      const other = msg.sender === username ? msg.receiver : msg.sender;
      if (
        !conversations[other] ||
        new Date(msg.timestamp).getTime() > conversations[other].timestamp.getTime()
      ) {
        conversations[other] = {
          user: other,
          lastMessage: msg.content,
          timestamp: new Date(msg.timestamp),
          seenByReceiver: msg.seenByReceiver || false,
          profile_pic: msg.sender === username ? msg.receiverPic : msg.senderPic
        };
      }
    });

    const sortedConversations = Object.values(conversations).sort((a, b) => b.timestamp - a.timestamp);

    res.render('inbox-chat', {
      currentUser,
      messages,
      otherUser,
      conversations: sortedConversations
    });
  } catch (err) {
    console.error('❌ Direct chat error:', err);
    res.status(500).send("Chat page error");
  }
});


// ✅ API: Send a message
app.post('/api/messages/send', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Login required' });

  const sender = req.session.user.username;
  const { receiver, content } = req.body;

  try {
    const savedMessage = await saveMessage({ sender, receiver, content });
    console.log('✅ Saved message to Firestore:', savedMessage);
    res.json({ success: true, message: savedMessage });
  } catch (err) {
    console.error('❌ /api/messages/send error:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});


// ✅ API: Get full message history between two users
app.get('/api/messages/conversation/:username', async (req, res) => {
  const user1 = req.session.user.username;
  const user2 = req.params.username;

  const convoRef = db.collection('messages')
    .where('participants', 'array-contains-any', [user1, user2])
    .orderBy('timestamp');

  const snapshot = await convoRef.get();
  const messages = [];

  snapshot.forEach(doc => {
    const data = doc.data();
    const participantsSorted = [user1, user2].sort().join(',');
    const dataSorted = data.participants.sort().join(',');
    if (participantsSorted === dataSorted) {
      messages.push({ id: doc.id, ...data });
    }
  });

  res.json(messages);
});

// ✅ Helper: Save message to Firestore with profile pics
async function saveMessage({ sender, receiver, content }) {
  const timestamp = new Date();

  const [senderDoc, receiverDoc] = await Promise.all([
    db.collection('users').doc(sender).get(),
    db.collection('users').doc(receiver).get()
  ]);

  const senderData = senderDoc.exists ? senderDoc.data() : {};
  const receiverData = receiverDoc.exists ? receiverDoc.data() : {};

  const message = {
    sender,
    receiver,
    participants: [sender, receiver].sort(),
    senderPic: senderData.profile_pic || null,
    receiverPic: receiverData.profile_pic || null,
    content: content.trim(),
    timestamp: admin.firestore.Timestamp.fromDate(timestamp),
    seenByReceiver: false
  };

  const ref = await db.collection('messages').add(message);
  return { id: ref.id, ...message };
}

// ✅ WebSocket setup
const connectedUsers = new Map();

io.on('connection', (socket) => {
  console.log('🔌 Socket connected:', socket.id);

  socket.on('joinRoom', ({ sender, receiver }) => {
  const room = [sender, receiver].sort().join('-');
  socket.join(room);
  connectedUsers.set(sender, socket.id);
  // Optional: you can log room membership
  console.log(`👥 ${sender} joined room ${room}`);
});

  socket.on('checkOnlineStatus', async ({ userToCheck }) => {
    if (!userToCheck) return;
    if (connectedUsers.has(userToCheck)) {
      socket.emit('userOnline', { username: userToCheck });
    } else {
      try {
        const doc = await db.collection('users').doc(userToCheck).get();
        const lastSeen = doc.exists ? doc.data().lastSeen : null;
        socket.emit('userOffline', { username: userToCheck, lastSeen });
      } catch (err) {
        console.error('❌ Failed to check user last seen:', err);
      }
    }
  });

  socket.on('chatMessage', async ({ sender, receiver, content }) => {
    console.log('✉️ Incoming socket message:', { sender, receiver, content });
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

  socket.on('reactToMessage', async ({ messageId, reactor, emoji }) => {
  try {
    const ref = db.collection('messages').doc(messageId);
    const doc = await ref.get();
    if (!doc.exists) return;

    const data = doc.data();
    const reactions = data.reactions || {};
    reactions[reactor] = emoji;

    await ref.update({ reactions });

    const updatedMsg = { id: messageId, ...data, reactions };

    const room = [data.sender, data.receiver].sort().join('-');

    // ✅ This ensures both users get the reaction update
    io.in(room).emit('reactionUpdated', updatedMsg);

  } catch (err) {
    console.error('❌ Reaction error:', err);
  }
});

  socket.on('disconnect', () => {
    for (const [username, id] of connectedUsers.entries()) {
      if (id === socket.id) {
        connectedUsers.delete(username);
        const lastSeen = new Date();
        db.collection('users').doc(username).update({ lastSeen })
          .catch(err => console.error('❌ Failed to update lastSeen:', err));
        socket.broadcast.emit('userOffline', {
          username,
          lastSeen: lastSeen.toISOString()
        });
        break;
      }
    }

    console.log('❌ Socket disconnected:', socket.id);
  });
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
