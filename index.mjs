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

const PUBLIC = "https://www.w3.org/ns/activitystreams#Public"
const MAX_PAGE_SIZE = 20

// Initialize Express
const app = express();

// Initialize SQLite
const db = new sqlite3.Database(DATABASE);

const run = promisify((...params) => { db.run(...params) })
const get = promisify((...params) => { db.get(...params) })
const all = promisify((...params) => { db.all(...params) })

const isString = value => typeof value === 'string' || value instanceof String;

db.run('CREATE TABLE IF NOT EXISTS user (username VARCHAR(255) PRIMARY KEY, passwordHash VARCHAR(255), actorId VARCHAR(255))');
db.run('CREATE TABLE IF NOT EXISTS object (id VARCHAR(255) PRIMARY KEY, owner VARCHAR(255), data TEXT)');
db.run('CREATE TABLE IF NOT EXISTS addressee (objectId VARCHAR(255), addresseeId VARCHAR(255))')

app.use(passport.initialize()); // Initialize Passport
app.use(express.json({type: ['application/json', 'application/activity+json']})) // for parsing application/json
app.use(express.urlencoded({ extended: true })) // for HTML forms

// Local Strategy for login/logout
passport.use(new LocalStrategy(
  function(username, password, done) {

  }
));

async function makeId(type) {
  return `https://${HOSTNAME}:${PORT}/${type.toLowerCase()}/${await nanoid()}`;
}

async function getObject(id) {
  const row = await get(`SELECT data FROM object WHERE id = ?`, [id])
  if (!row) {
    return null
  }
  return JSON.parse(row.data)
}

async function getOwner(id) {
  const row = await get(`SELECT owner FROM object WHERE id = ?`, [id])
  if (!row) {
    return null
  }
  return getObject(row.owner)
}

async function getAddressees(id) {
  const rows = await all(`SELECT addresseeId FROM addressee WHERE objectId = ?`, [id])
  return rows.map((row) => row.addresseeId)
}

async function toObject(value) {
  if (isString(value)) {
    return getObject(value)
  } else {
    return value
  }
}

async function saveObject(type, data, owner=null, addressees=[]) {
  data = data || {};
  data.id = data.id || await makeId(type)
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
  return data;
}

async function patchObject(id, patch) {
  let row = await get(`SELECT data from object WHERE id = ?`, [id])
  if (!row) {
    throw new Error(`No object with ID ${id}`)
  }
  const merged = {...JSON.parse(row.data), ...patch, updated: new Date().toISOString()}
  await run(`UPDATE object SET data = ? WHERE id = ?`, [JSON.stringify(merged), id])
  return merged
}

const emptyOrderedCollection = async(name, owner, addressees) => {
  const id = await makeId('OrderedCollection')
  const page = await saveObject(
    'OrderedCollectionPage',
    {
      'orderedItems': [],
      'partOf': id
    },
    owner,
    addressees
  )
  return await saveObject(
    'OrderedCollection',
    {
      id: id,
      name: name,
      totalItems: 0,
      first: page.id,
      last: page.id
    },
    owner,
    addressees
  )
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

async function isUser(id) {
  const row = await get("SELECT username FROM user WHERE actorId = ?", [id])
  return !!row
}

async function memberOf(objectId, collectionId) {
  const coll = getObject(collectionId)
  switch (coll.type) {
    case "Collection":
    case "OrderedCollection":
      if (coll.orderedItems) {
        return objectId in coll.orderedItems
      } else if (coll.first) {
        return memberOf(objectId, coll.first)
      }
      break
    case "CollectionPage":
    case "OrderedCollectionPage":
      if (coll.orderedItems && (objectId in coll.orderedItems)) {
        return true;
      }
      if (coll.next) {
        return memberOf(objectId, coll.next)
      }
      return false
  }
}

async function saveActivity(data, owner) {
  data = data || {};
  data.type = data.type || 'Activity';
  data.id = data.id || await makeId(data.type)
  data.actor = owner.id
  const addressees = ['to', 'cc', 'bto', 'bcc']
    .map((prop) => data[prop])
    .filter((a) => a)
    .flat()
  delete data['bto']
  delete data['bcc']
  return saveObject(data.type, data, owner, addressees)
}

async function applyActivity(activity, owner) {
  switch (activity.type) {
    case "Follow":
      if (!activity.object) {
        throw new createError.BadRequest("No object followed")
      }
      if (await memberOf(activity.object, owner.following)) {
        throw new createError.BadRequest("Already following")
      }
      const following = await getObject(owner.following)
      await prependObject(following, activity.object)
      if (await isUser(activity.object)) {
        const other = await getObject(activity.object)
        const followers = await getObject(other.followers)
        await prependObject(followers, owner)
      }
      return
    default:
      return
  }
}

async function prependObject(collection, object) {
  collection = await toObject(collection)
  object = await toObject(object)
  if (collection.orderedItems) {
    await patchObject(collection.id, {totalItems: collection.totalItems + 1, orderedItems: [object.id, ...collection.orderedItems]})
  } else if (collection.first) {
    const first = await getObject(collection.first)
    if (first.orderedItems.length < MAX_PAGE_SIZE) {
      await patchObject(first.id, {orderedItems: [object.id, ...first.orderedItems]})
      await patchObject(collection.id, {totalItems: collection.totalItems + 1})
    } else {
      const owner = await getOwner(collection.id)
      const addressees = await getAddressees(collection.id)
      const newFirst = await saveObject('OrderedCollectionPage', {partOf: collection.id, 'orderedItems': [object.id], next: first.id}, owner, addressees)
      await patchObject(collection.id, {totalItems: collection.totalItems + 1, first: newFirst.id})
      await patchObject(first.id, {prev: newFirst.id})
    }
  }
}

async function getAllMembers(id) {
  const obj = await getObject(id)
  let cur = []
  switch (obj.type) {
    case 'CollectionPage':
    case 'OrderedCollectionPage':
      cur = obj.items || obj.orderedItems || [];
      if (obj.next) {
        cur = cur.concat(await getAllMembers(obj.next))
      }
    case 'Collection':
    case 'OrderedCollection':
      if (obj.first) {
        cur = getAllMembers(obj.first)
      }
  }
  return cur
}

async function distributeActivity(activity, owner) {

  // Add it to the owner inbox!

  const ownerInbox = await getObject(owner.inbox)
  await prependObject(ownerInbox, activity, owner, [PUBLIC])

  // Get all the addressees

  const addressees = await getAddressees(activity.id)

  // Expand public, followers, other lists

  const expanded = (await Promise.all(addressees.map(async (addressee) => {
    if (addressee === PUBLIC) {
      return await getAllMembers(owner.followers)
    } else {
      const obj = await getObject(addressee)
      const objOwner = await getOwner(addressee)
      if (obj &&
          objOwner.id === owner.id &&
          -1 !== ['Collection', 'OrderedCollection'].indexOf(obj.type)) {
          return await getAllMembers(addressee)
      }
    }
    return addressee
  }))).filter((v, i, a) => v && a.indexOf(v) === i && v !== owner.id).flat()

  // Deliver to each of the expanded addressees

  await Promise.all(expanded.map((async (addressee) => {
    const row = await get(`SELECT username FROM user WHERE actorId = ?`, [addressee])
    if (row) {
      // Local delivery
      const user = await getObject(addressee);
      const inbox = await getObject(user.inbox);
      return prependObject(inbox, activity)
    } else {
      // Remote delivery
      return null
    }
  })))
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
    const actorId = await makeId('Person')
    const data = {name: username, id: actorId};
    const props = ['inbox', 'outbox', 'followers', 'following', 'liked']
    for (let prop of props) {
      const coll = await emptyOrderedCollection(`${username}'s ${prop}`, actorId, [PUBLIC])
      data[prop] = coll.id
    }
    await saveObject('Person', data, null, [PUBLIC])
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
      <p>Registered <a class="actor" href="${actorId}">${username}</a></p>
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
  const addressees = await getAddressees(full)
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
  data['@context'] = data['@context'] || 'https://www.w3c.org/ns/activitystreams'
  res.set('Content-Type', 'application/activity+json')
  res.json(data)
}))

app.post('/:type/:id',
  expressjwt({ secret: KEY_DATA, credentialsRequired: false, algorithms: ["RS256"] }),
  wrap(async(req, res) => {
  const full = req.protocol + '://' + req.get('host') + req.originalUrl;
  const type = req.params.type
  const id = req.params.id
  const obj = await get('SELECT data, owner FROM object WHERE id = ?', [full])
  if (!obj) {
    throw new createError.NotFound('Object not found')
  }
  if (!obj.data || !obj.owner) {
    throw new createError.InternalServerError('Invalid object')
  }
  const owner = await getObject(obj.owner)
  if (!owner) {
    throw new createError.InternalServerError('No owner found for object')
  }
  if (full === owner.outbox) {
    const outbox = JSON.parse(obj.data)
    if (req.auth?.subject !== obj.owner) {
      throw new createError.Forbidden('You cannot post to this outbox')
    }
    const activity = await saveActivity(req.body, owner.id)
    await applyActivity(activity, owner)
    await prependObject(outbox, activity)
    await distributeActivity(activity, owner)
    activity['@context'] = activity['@context'] || 'https://www.w3c.org/ns/activitystreams'
    res.status(200)
    res.set('Content-Type', 'application/activity+json')
    res.json(activity)
  } else if (full === owner.inbox) {
    throw new createError.NotImplemented('Unimplemented endpoint')
  } else {
    throw new createError.MethodNotAllowed('You cannot POST to this object')
  }
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
