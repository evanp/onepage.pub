import express from 'express'
import sqlite3 from 'sqlite3';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import fs from 'fs';
import https from 'https';
import wrap from 'express-async-handler';

const DATABASE = process.env.OPP_DATABASE || ':memory:'
const HOSTNAME = process.env.OPP_HOSTNAME || 'localhost'
const PORT = process.env.OPP_PORT || 3000
const KEY = process.env.OPP_KEY || 'server.key'
const CERT = process.env.OPP_CERT || 'server.crt'

// Initialize Express
const app = express();

// Initialize SQLite
const db = new sqlite3.Database(DATABASE);
db.run('CREATE TABLE IF NOT EXISTS user (username VARCHAR(255) PRIMARY KEY, passwordHash VARCHAR(255), objectId VARCHAR(255))');
db.run('CREATE TABLE IF NOT EXISTS object (id VARCHAR(255) PRIMARY KEY, data TEXT)');
db.run('CREATE TABLE IF NOT EXISTS member (objectId VARCHAR(255), collectionId VARCHAR(255), FOREIGN KEY(objectId) REFERENCES object(id), FOREIGN KEY(collectionId) REFERENCES collection(id))');

// Initialize Passport
app.use(passport.initialize());
// app.use(passport.session());

// Local Strategy for login/logout
passport.use(new LocalStrategy(
  function(username, password, done) {

  }
));

app.get('/', wrap(async(req, res) => {
  const url = req.protocol + '://' + req.get('host') + req.originalUrl;
  res.set('Content-Type', 'application/activity+json')
  res.json({
    '@context': 'https://w3c.org/ns/activitystreams',
    'id': url,
    'name': process.OPP_NAME || 'One Page Pub',
    'type': 'Service'
  })
}))

// Routes for ActivityPub
app.get('/:username', wrap(async (req, res) => {
  // TODO: handle actor
}));

app.get('/:username/inbox', wrap(async (req, res) => {
  // TODO: handle inbox
}));

app.post('/:username/inbox', wrap(async (req, res) => {
  // TODO: handle inbox
}));

// and so on...

// Routes for authentication
app.post('/register', wrap(async (req, res) => {
  // TODO: handle registration
}));

app.post('/login', passport.authenticate('local'), wrap(async (req, res) => {
  // TODO: handle login
}));

app.post('/logout', wrap(async (req, res) => {
  // TODO: handle logout
}));

// Start server with SSL
https.createServer({
  key: fs.readFileSync(KEY),
  cert: fs.readFileSync(CERT)
}, app)
.listen(PORT, HOSTNAME, () => {
  console.log(`Listening on ${HOSTNAME}:${PORT}`)
})
