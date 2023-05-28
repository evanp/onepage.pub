import express from 'express'
import sqlite3 from 'sqlite3';
import passport from 'passport';
import LocalStrategy from 'passport-local';
import fs from 'fs';
import https from 'https';
import wrap from 'express-async-handler';
import createError from 'http-errors';
import { nanoid } from 'nanoid/async';
import bcrypt from 'bcrypt';

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
app.use(express.json()) // for parsing application/json
app.use(express.urlencoded({ extended: true })) // for parsing application/x-www-form-urlencoded

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

app.get('/register', wrap(async(req, res) => {
  res.type('html')
  res.status(200)
  res.end(`
    <html>
    <head>
    <title>Register</title>
    </head>
    <body>
    <form method="POST" action="/register">
    <label for="username">Username</label> <input type="text" name="username" placeholder="Username" />
    <label for="password">Password</label> <input type="password" name="password" placeholder="Password" />
    <label for="confirmation">Confirm</label> <input type="password" name="confirmation" placeholder="Confirm Password" />
    </form>
    </body>
    </html>`)
}))

app.post('/register', wrap(async(req, res) => {
  if (req.get('Content-Type') !== 'application/x-www-form-urlencoded') {
    throw new createError.BadRequest('Invalid Content-Type');
  }
  if (!req.body.username) {
    throw new createError.BadRequest('Username is required')
  }
  if (!req.body.password) {
    throw new createError.BadRequest('Password is required')
  }
  if (req.body.password !== req.body.confirmation) {
    throw new createError.BadRequest('Passwords do not match')
  } else {
    const username = req.body.username
    const password = req.body.password
    const passwordHash = await bcrypt.hash(password, 10)
    db.run('INSERT INTO user (username, passwordHash) VALUES (?, ?)', [username, passwordHash])
    res.type('html')
    res.status(200)
    res.end(`
      <html>
      <head>
      <title>Registered</title>
      </head>
      <body>
      <p>Registered ${username}</p>
      </body>
      </html>`)
  }
}))

app.use(wrap(async(err, req, res, next) => {
  if (createError.isHttpError(err)) {
    res.status(err.statusCode)
    if (res.expose) {
      res.end(err.message)
    } else {
      res.end('Internal Server Error')
    }
  } else {
    res.status(500)
    res.end('Internal Server Error')
  }
}))

// Start server with SSL
https.createServer({
  key: fs.readFileSync(KEY),
  cert: fs.readFileSync(CERT)
}, app)
.listen(PORT, HOSTNAME, () => {
  console.log(`Listening on ${HOSTNAME}:${PORT}`)
})
