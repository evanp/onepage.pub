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
import crypto from 'crypto';

const sign = promisify(jwt.sign);
const generateKeyPair = promisify(crypto.generateKeyPair);

const DATABASE = process.env.OPP_DATABASE || ':memory:'
const HOSTNAME = process.env.OPP_HOSTNAME || 'localhost'
const PORT = process.env.OPP_PORT || 3000
const KEY = process.env.OPP_KEY || 'server.key'
const CERT = process.env.OPP_CERT || 'server.crt'
const KEY_DATA = fs.readFileSync(KEY)
const CERT_DATA = fs.readFileSync(CERT)

const AS_CONTEXT = 'https://www.w3.org/ns/activitystreams'
const SEC_CONTEXT = 'https://w3id.org/security'
const CONTEXT = [AS_CONTEXT, SEC_CONTEXT]

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

db.run('CREATE TABLE IF NOT EXISTS user (username VARCHAR(255) PRIMARY KEY, passwordHash VARCHAR(255), actorId VARCHAR(255), privateKey TEXT)');
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
  if (PORT === 443) {
    return `https://${HOSTNAME}/${type.toLowerCase()}/${await nanoid()}`;
  } else {
    return `https://${HOSTNAME}:${PORT}/${type.toLowerCase()}/${await nanoid()}`;
  }
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

async function toId(value) {
  if (typeof value == "undefined") {
    return null;
  } else if (value == null) {
    return null;
  } else if (isString(value)) {
    return value;
  } else if (typeof value == "object") {
    return value.id || value['@id']
  } else {
    throw new Error(`cannot coerce to an ID: ${value} (${typeof value})`)
  }
}

async function getRemoteObject(value) {
  const id = await toId(value)
  const obj = await getObject(id)
  if (obj) {
    return obj
  } else {
    const res = await fetch(id, {
      headers: {'Accept': 'application/activity+json, application/ld+json, application/json'}
    })
    if (res.status !== 200) {
      return null
    } else {
      return res.json()
    }
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

async function canRead(object, subject, owner=null, addressees=null) {
  const objectId = await toId(object)
  const subjectId = await toId(subject)
  owner = owner || await getOwner(objectId)
  addressees = addressees || await getAddressees(objectId)
  const ownerId = await toId(owner)
  const addresseeIds = await Promise.all(addressees.map(toId))
  // anyone can read if it's public

  if (-1 !== addresseeIds.indexOf(PUBLIC)) {
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
  if (-1 !== addresseeIds.indexOf(subjectId)) {
    return true;
  }
  // if they're a member of any addressed collection
  for (let addresseeId of addresseeIds) {
    if (await memberOf(subjectId, addresseeId)) {
      return true
    }
  }
  // Otherwise, can't read
  return false;
}

async function isUser(object) {
  const id = await toId(object)
  const row = await get("SELECT username FROM user WHERE actorId = ?", [id])
  return !!row
}

async function memberOf(object, collection) {
  const objectId = await toId(object)
  collection = await toObject(collection)
  switch (collection.type) {
    case "Collection":
    case "OrderedCollection":
      if (collection.orderedItems) {
        return -1 !== collection.orderedItems.indexOf(objectId)
      } else if (collection.items) {
          return -1 !== collection.items.indexOf(objectId)
      } else if (collection.first) {
        return await memberOf(objectId, collection.first)
      }
      break
    case "CollectionPage":
    case "OrderedCollectionPage":
      if (collection.orderedItems) {
        return -1 !== collection.orderedItems.indexOf(objectId)
      } else if (collection.items) {
          return -1 !== collection.items.indexOf(objectId)
      } else if (collection.next) {
        return await memberOf(objectId, collection.next)
      }
      return false
    default:
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

async function applyRemoteActivity(activity, remote, owner) {
  switch (activity.type) {
    case "Follow":
      if (toId(activity.object) == toId(owner)) {
        if (await memberOf(remote, owner.followers)) {
          throw new Error("Already following")
        }
        const followers = await getObject(owner.followers)
        await prependObject(followers, remote)
      }
      break
    default:
      break
  }
  return
}

async function prependObject(collection, object) {
  collection = await toObject(collection)
  const objectId = await toId(object)
  if (collection.orderedItems) {
    await patchObject(collection.id, {totalItems: collection.totalItems + 1, orderedItems: [objectId, ...collection.orderedItems]})
  } else if (collection.first) {
    const first = await getObject(collection.first)
    if (first.orderedItems.length < MAX_PAGE_SIZE) {
      await patchObject(first.id, {orderedItems: [objectId, ...first.orderedItems]})
      await patchObject(collection.id, {totalItems: collection.totalItems + 1})
    } else {
      const owner = await getOwner(collection.id)
      const addressees = await getAddressees(collection.id)
      const newFirst = await saveObject('OrderedCollectionPage', {partOf: collection.id, 'orderedItems': [objectId], next: first.id}, owner, addressees)
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

async function signRequest(keyId, privateKey, method, url, date) {
  url = (isString(url)) ? new URL(url) : url;
  const target = (url.search && url.search.length) ?
    `${url.pathname}?${url.search}` :
    `${url.pathname}`
  let data = `(request-target): ${method.toLowerCase()} ${target}\n`
  data += `host: ${url.host}\n`
  data += `date: ${date}`
  const signer = crypto.createSign('sha256');
	signer.update(data);
	const signature = signer.sign(privateKey).toString('base64');
	signer.end();
  const header = `keyId="${keyId}",headers="(request-target) host date",signature="${signature.replace(/"/g, '\\"')}",algorithm="rsa-sha256"`;
  return header
}

async function validateSignature(sigHeader, req) {
  const parts = Object.fromEntries(sigHeader.split(',').map((clause) => {
    let match = clause.match(/^\s*(\w+)\s*=\s*"(.*?)"\s*$/)
    return [match[1], match[2].replace(/\\"/, '"')]
  }))
  if (!parts.keyId || !parts.headers || !parts.signature || !parts.algorithm) {
    return null
  }
  if (parts.algorithm != 'rsa-sha256') {
    return null
  }
  let lines = []
  for (let name of parts.headers.split(' ')) {
    if (name == '(request-target)') {
      lines.push(`(request-target): ${req.method.toLowerCase()} ${req.originalUrl}`)
    } else {
      let value = req.get(name)
      lines.push(`${name}: ${value}`)
    }
  }
  let data = lines.join('\n')
  const publicKey = await getRemoteObject(parts.keyId)
  if (!publicKey || !publicKey.owner || !publicKey.publicKeyPem) {
    return null
  }
  const verifier = crypto.createVerify('sha256');
	verifier.write(data);
	verifier.end();
  if (verifier.verify(publicKey.publicKeyPem, Buffer.from(parts.signature, 'base64'))) {
    return await getRemoteObject(publicKey.owner)
  } else {
    return null
  }
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

  const body = JSON.stringify(activity)
  const {privateKey} = await get('SELECT privateKey FROM user WHERE actorId = ?', [owner.id])
  const keyId = owner.publicKey.id;

  await Promise.all(expanded.map((async (addressee) => {
    const row = await get(`SELECT username FROM user WHERE actorId = ?`, [addressee])
    if (row) {
      // Local delivery
      const user = await getObject(addressee);
      const inbox = await getObject(user.inbox);
      return prependObject(inbox, activity)
    } else {
      const other = await getRemoteObject(addressee);
      const inbox = await toId(other.inbox)
      const date = new Date().toUTCString()
      const signature = await signRequest(keyId, privateKey, 'POST', inbox, date)
      const res = await fetch(inbox, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/activity+json; charset=utf-8',
          'Signature': signature,
          'Date': date
        },
        body: body
      })
      const resBody = await res.text()
    }
  })))
}

app.get('/', wrap(async(req, res) => {
  const url = req.protocol + '://' + req.get('host') + req.originalUrl;
  res.set('Content-Type', 'application/activity+json')
  res.json({
    '@context': CONTEXT,
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
    const {publicKey, privateKey} = await generateKeyPair(
      'rsa',
      {
        modulusLength: 2048,
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'pem'
        },
        publicKeyEncoding: {
          type: 'pkcs1',
          format: 'pem'
        }
      }
    )
    const {id, type, owner, publicKeyPem} = await saveObject('Key', {owner: actorId, publicKeyPem: publicKey}, actorId, [PUBLIC])
    data['publicKey'] = {id, type, owner, publicKeyPem}
    await saveObject('Person', data, actorId, [PUBLIC])
    await run('INSERT INTO user (username, passwordHash, actorId, privateKey) VALUES (?, ?, ?, ?)', [username, passwordHash, actorId, privateKey])
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
  const obj = await get('SELECT data, owner FROM object WHERE id = ?', [full])
  if (!obj) {
    throw new createError.NotFound('Object not found')
  }
  if (!obj.data) {
    throw new createError.InternalServerError('Invalid object')
  }
  const addressees = await getAddressees(full)
  if (!(await canRead(full, req.auth?.subject, obj.owner, addressees))) {
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
  for (let name of ['items', 'orderedItems']) {
    if (name in data && Array.isArray(data[name])) {
      const len = data[name].length
      for (let i = len - 1; i >= 0; i--) {
        const item = data[name][i];
        const itemId = await toId(item);
        if (!(await canRead(itemId, req.auth?.subject))) {
          data[name].splice(i, 1)
        }
      }
    }
  }
  data['@context'] = data['@context'] || CONTEXT
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
    activity['@context'] = activity['@context'] || CONTEXT
    res.status(200)
    res.set('Content-Type', 'application/activity+json')
    res.json(activity)
  } else if (full === owner.inbox) { // remote delivery
    const sigHeader = req.headers['signature']
    if (!sigHeader) {
      throw new createError.Unauthorized('HTTP signature required')
    }
    const remote = await validateSignature(sigHeader, req)
    if (!remote) {
      throw new createError.Unauthorized('Invalid HTTP signature')
    }
    if (await isUser(remote)) {
      throw new createError.Forbidden('Remote delivery only')
    }
    const activity = await saveActivity(req.body, remote)
    await applyRemoteActivity(activity, remote, owner)
    await prependObject(owner.inbox, activity)
    res.status(202)
    res.set('Content-Type', 'application/activity+json')
    res.json(activity)
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
