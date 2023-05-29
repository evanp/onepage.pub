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
import { expressjwt } from "express-jwt";
import jwt from 'jsonwebtoken';
import { promisify } from 'util';

const sign = promisify(jwt.sign);

const DATABASE = process.env.OPP_DATABASE || ':memory:'
const HOSTNAME = process.env.OPP_HOSTNAME || 'localhost'
const PORT = process.env.OPP_PORT || 3000
const KEY = process.env.OPP_KEY || 'server.key'
const CERT = process.env.OPP_CERT || 'server.crt'
const KEY_DATA = fs.readFileSync(KEY)
const CERT_DATA = fs.readFileSync(CERT)
const PUBLIC = "https://w3.org/ns/activitypub#Public"

// Initialize Express
const app = express();

// Initialize SQLite
const db = new sqlite3.Database(DATABASE);

const run = promisify((...params) => { db.run(...params) })
const get = promisify((...params) => { db.get(...params) })
const all = promisify((...params) => { db.all(...params) })

const emptyOrderedCollection = async(name, owner, addressees) => {
  return saveObject(
    'OrderedCollection',
    {
      name: name,
      totalItems: 0,
      first: await saveObject('OrderedCollectionPage', {'orderedItems': []}, owner, addressees)
    },
    owner,
    addressees
  )
}

db.run('CREATE TABLE IF NOT EXISTS user (username VARCHAR(255) PRIMARY KEY, passwordHash VARCHAR(255), actorId VARCHAR(255))');
db.run('CREATE TABLE IF NOT EXISTS object (id VARCHAR(255) PRIMARY KEY, owner VARCHAR(255), data TEXT)');
db.run('CREATE TABLE IF NOT EXISTS addressee (objectId VARCHAR(255), addresseeId VARCHAR(255))')

app.use(passport.initialize()); // Initialize Passport
app.use(express.json()) // for parsing application/json
app.use(express.urlencoded({ extended: true })) // for HTML forms

// Local Strategy for login/logout
passport.use(new LocalStrategy(
  function(username, password, done) {

  }
));

async function saveObject(type, data, owner=null, addressees=[]) {
  data = data || {};
  data.id = data.id || `https://${HOSTNAME}:${PORT}/${type.toLowerCase()}/${await nanoid()}`;
  data.type = data.type || type || 'Object';
  data.updated = new Date().toISOString();
  data.published = data.published || data.updated;
  // self-ownership
  owner = owner || data.id;
  await run('INSERT INTO object (id, owner, data) VALUES (?, ?, ?)', [data.id, owner, JSON.stringify(data)]);
  addressees.forEach(async(addressee) =>
    run(
      'INSERT INTO addressee (objectId, addresseeId) VALUES (?, ?)',
      [data.id, addressee]
    )
  )
  return data.id;
}

async function patchObject(id, patch) {
  let row = await get(`SELECT data from object WHERE id = ?`, [id])
  if (!row) {
    throw new Error(`No object with ID ${id}`)
  }
  const merged = {...JSON.parse(row.data), ...patch, updated: new Date().toISOString()}
  await run(`UPDATE object SET data = ? WHERE id = ?`, [JSON.stringify(merged), id])
}

async function canRead(objectId, subjectId, ownerId, addressees) {
  // anyone can read if it's public
  if (PUBLIC in addressees) {
    return true;
  }
  // otherwise, unauthenticated can't read
  if (!subjectId) {
    return false;
  }
  // owner can always read
  if (subjectId === ownerId) {
    return true;
  }
  // direct addressees can always read
  if (subjectId in addressees) {
    return true;
  }
  // if they're a member of any addressed collection
  if (addressees.some(async(addresseeId) => await memberOf(subjectId, addresseeId))) {
    return true;
  }
  // Otherwise, can't read
  return false;
}

async function memberOf(objectId, collectionId) {
  const data = await get(`SELECT data from object where id = ?`, [collectionId])
  if (!data) {
    return false
  }
  const coll = JSON.parse(data)
  switch (coll.type) {
    case "Collection":
    case "OrderedCollection":
      if (coll.items) {
        return objectId in coll.items
      } else if (coll.first) {
        return memberOf(objectId, coll.first)
      }
      break
    case "CollectionPage":
    case "OrderedCollectionPage":
      if (coll.items && (objectId in coll.items)) {
        return true;
      }
      if (coll.next) {
        return memberOf(objectId, coll.next)
      }
      return false
  }
}

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
    // Create the person; self-own!
    const actorId = await saveObject('Person', {name: username}, null, [PUBLIC])
    // Patch with collections
    await patchObject(actorId, {
      'inbox': await emptyOrderedCollection(`${username}'s Inbox`, actorId, [PUBLIC]),
      'outbox': await emptyOrderedCollection(`${username}'s Outbox`, actorId, [PUBLIC]),
      'followers': await emptyOrderedCollection(`${username}'s Followers`, actorId, [PUBLIC]),
      'following': await emptyOrderedCollection(`${username}'s Following`, actorId, [PUBLIC]),
      'liked': await emptyOrderedCollection(`${username}'s Liked`, actorId, [PUBLIC])
    })
    await run('INSERT INTO user (username, passwordHash, actorId) VALUES (?, ?, ?)', [username, passwordHash, actorId])
    const token = await sign(
      {
        subject: actorId,
        issuer: req.protocol + '://' + req.get('host') + req.originalUrl
      },
      KEY_DATA,
      { algorithm: 'RS256' }
    )
    res.type('html')
    res.status(200)
    res.end(`
      <html>
      <head>
      <title>Registered</title>
      </head>
      <body>
      <p>Registered ${username}</p>
      <p>Personal access token is <span class="token">${token}</span>
      </body>
      </html>`)
  }
}))

app.get('/.well-known/webfinger', wrap(async(req, res) => {
  const resource = req.query.resource
  if (!resource) {
    throw new createError.BadRequest('Missing resource')
  }
  if (!resource.startsWith('acct:')) {
    throw new createError.BadRequest('Resource must start with acct:')
  }
  if (!resource.includes('@')) {
    throw new createError.BadRequest('Resource must contain @')
  }
  const [username, hostname] = resource.substr('acct:'.length).split('@')
  if (hostname !== req.get('host')) {
    throw new createError.NotFound('Hostname does not match')
  }
  const user = await get('SELECT username, actorId FROM user WHERE username = ?', [username])
  if (!user) {
    throw new createError.NotFound('User not found')
  }
  if (!user.username) {
    throw new createError.NotFound('User not found')
  }
  if (!user.actorId) {
    throw new createError.InternalServerError('Invalid user')
  }
  res.set('Content-Type', 'application/jrd+json')
  res.json({
    'subject': resource,
    'links': [
      {
        'rel': 'self',
        'type': 'application/activity+json',
        'href': user.actorId
      }
    ]
  })
}))

app.get('/:type/:id',
  expressjwt({ secret: KEY_DATA, credentialsRequired: false, algorithms: ["RS256"] }),
  wrap(async(req, res) => {
  const full = req.protocol + '://' + req.get('host') + req.originalUrl;
  const type = req.params.type
  const id = req.params.id
  const obj = await get('SELECT data, owner FROM object WHERE id = ?', [full])
  if (!obj) {
    throw new createError.NotFound('Object not found')
  }
  if (!obj.data) {
    throw new createError.InternalServerError('Invalid object')
  }
  const addressees = await all('SELECT addresseeId FROM addressee where objectId = ?', [full])
  if (!canRead(full, req.auth?.subject, obj.owner, addressees)) {
    if (req.auth?.subject) {
      throw new createError.Forbidden('Not authorized to read this object')
    } else {
      throw new createError.Unauthorized('You must provide credentials to read this object')
    }
  }
  const data = JSON.parse(obj.data)
  if (data.type?.toLowerCase() !== type) {
    throw new createError.InternalServerError('Invalid object type')
  }
  data['@context'] = data['@context'] || 'https://w3c.org/ns/activitystreams'
  res.set('Content-Type', 'application/activity+json')
  res.json(data)
}))

app.use((err, req, res, next) => {
  if (createError.isHttpError(err)) {
    res.status(err.statusCode)
    if (res.expose) {
      res.json({message: err.message})
    } else {
      res.json({message: err.message})
    }
  } else {
    res.status(500)
    res.json({message: err.message})
  }
})

// Start server with SSL
https.createServer({
  key: KEY_DATA,
  cert: CERT_DATA
}, app)
.listen(PORT, HOSTNAME, () => {
  console.log(`Listening on ${HOSTNAME}:${PORT}`)
})
