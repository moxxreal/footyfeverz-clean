const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./forum.db');

// Create threads table
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    league TEXT,
    title TEXT,
    content TEXT,
    user TEXT DEFAULT 'guest'
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    thread_id INTEGER,
    user TEXT,
    text TEXT,
    FOREIGN KEY(thread_id) REFERENCES threads(id)
  )`);
});

db.close();
console.log("✅ Database initialized");


// Create users table
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);
});

db.close();
console.log("✅ Database initialized");
