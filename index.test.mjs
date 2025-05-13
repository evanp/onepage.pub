import { describe, before, after, it } from 'node:test'
import { spawn } from 'node:child_process'
import assert from 'node:assert'
import querystring from 'node:querystring'
import crypto from 'node:crypto'
import path from 'node:path'
import https from 'node:https'
import fs from 'node:fs'
import { promisify } from 'node:util'
import { Blob } from 'node:buffer'

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0

const MAIN_PORT = 50941 // V
const REMOTE_PORT = 51996 // Cr
const CLIENT_PORT = 54938 // Mn
const THIRD_PORT = 55845 // Fe
const FOURTH_PORT = 58933 // Co
const FIFTH_PORT = 58693 // Ni

const CLIENT_ID = `https://localhost:${CLIENT_PORT}/client`
const REDIRECT_URI = `https://localhost:${CLIENT_PORT}/oauth/callback`
const AS2 =
  'application/ld+json; profile="https://www.w3.org/ns/activitystreams"'
const AS2_CONTEXT = 'https://www.w3.org/ns/activitystreams'
const AS2_MEDIA_TYPE = 'application/activity+json; charset=utf-8'
const PUBLIC = 'https://www.w3.org/ns/activitystreams#Public'

const generateKeyPair = promisify(crypto.generateKeyPair)

const delay = (t) => new Promise((resolve) => setTimeout(resolve, t))

const startServer = (port = MAIN_PORT, props = {}) => {
  return new Promise((resolve, reject) => {
    const server = spawn('node', ['index.mjs'], {
      env: {
        OPP_HOSTNAME: 'localhost',
        ...process.env,
        ...props,
        OPP_PORT: port
      }
    })
    server.on('error', reject)
    server.stdout.on('data', (data) => {
      if (data.toString().includes('Listening')) {
        resolve(server)
      }
      console.log(`SERVER ${port}: ${data.toString()}`)
    })
    server.stderr.on('data', (data) => {
      console.log(`SERVER ${port} ERROR: ${data.toString()}`)
    })
  })
}

const defaultClient = {
  '@context': [AS2_CONTEXT, 'https://purl.archive.org/socialweb/oauth'],
  type: 'Application',
  id: CLIENT_ID,
  redirectURI: REDIRECT_URI,
  nameMap: {
    en: 'Test scripts for onepage.pub'
  }
}

const startClientServer = (
  port = CLIENT_PORT,
  client = JSON.stringify(defaultClient),
  contentType = AS2
) => {
  return new Promise((resolve, reject) => {
    const options = {
      key: fs.readFileSync('localhost.key'),
      cert: fs.readFileSync('localhost.crt')
    }
    const server = https.createServer(options, (req, res) => {
      if (req.url.startsWith('/client')) {
        res.writeHead(200, {
          'Content-Type': contentType
        })
        res.end(client)
      } else {
        res.writeHead(404)
        res.end()
      }
    })

    server.on('error', reject)

    server.listen(port, 'localhost', () => {
      resolve(server)
    })
  })
}

const registerUser = (() => {
  let i = 100
  return async (port = MAIN_PORT) => {
    i++
    const username = `testuser${i}`
    const password = `testpassword${i}`
    const reg = await fetch(`https://localhost:${port}/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: querystring.stringify({
        username,
        password,
        confirmation: password
      })
    })
    const text = await reg.text()
    const token = text.match(/<span class="token">(.*?)<\/span>/)[1]
    const cookie = reg.headers.get('Set-Cookie')
    return [username, token, password, cookie]
  }
})()

const userToActor = async (username, port = MAIN_PORT) => {
  const res = await fetch(
    `https://localhost:${port}/.well-known/webfinger?resource=acct:${username}@localhost:${port}`
  )
  const obj = await res.json()
  const actorId = obj.links[0].href
  const actorRes = await fetch(actorId)
  return await actorRes.json()
}

const registerActor = async (port = MAIN_PORT) => {
  const [username, token, , cookie] = await registerUser(port)
  const actor = await userToActor(username, port)
  return [actor, token, cookie]
}

const doActivity = async (actor, token, activity) => {
  const res = await fetch(actor.outbox, {
    method: 'POST',
    headers: {
      'Content-Type':
        'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
      Authorization: `Bearer ${token}`
    },
    body: JSON.stringify(activity)
  })
  if (res.status !== 201) {
    const body = await res.text()
    throw new Error(`Bad status code ${res.status}: ${body}`)
  }
  return await res.json()
}

const failActivity = async (actor, token, activity) => {
  const res = await fetch(actor.outbox, {
    method: 'POST',
    headers: {
      'Content-Type':
        'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
      Authorization: `Bearer ${token}`
    },
    body: JSON.stringify(activity)
  })
  const body = await res.text()
  if (res.status >= 200 && res.status <= 299) {
    throw new Error(
      `Good status code ${res.status} for activity that should fail: ${body}`
    )
  }
  return res.status
}

const getObject = async (id, token = null) => {
  const headers = {
    Accept:
      'application/ld+json; profile="https://www.w3.org/ns/activitystreams",application/activity+json,application/json'
  }
  if (token) {
    headers.Authorization = `Bearer ${token}`
  }
  const res = await fetch(id, {
    headers
  })
  if (res.status !== 200) {
    throw new Error(`Bad status code ${res.status}`)
  }
  return await res.json()
}

const getMembers = async (collection, token = null) => {
  const url = typeof collection === 'string' ? collection : collection.id
  if (!url) {
    throw new Error(`Invalid collection ${collection}`)
  }
  const coll = await getObject(url, token)
  if ('orderedItems' in coll) {
    return coll.orderedItems
  } else if ('items' in coll) {
    return coll.items
  } else if ('first' in coll) {
    let members = []
    let pageObj = null
    for (let page = coll.first; page; page = pageObj.next) {
      const pageId = typeof page === 'string' ? page : page.id
      pageObj = await getObject(pageId, token)
      for (const prop of ['orderedItems', 'items']) {
        if (prop in pageObj) {
          members = members.concat(pageObj[prop])
        }
      }
    }
    return members
  } else {
    throw new Error(
      `Invalid collection ${url}: no items, orderedItems, or first`
    )
  }
}

const isInStream = async (collection, object, token = null) => {
  const objectId = typeof object === 'string' ? object : object.id
  const members = await getMembers(collection, token)
  return members.some((item) => item.id === objectId)
}

const getProxy = async (id, actor, token) => {
  const res = await fetch(actor.endpoints.proxyUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Bearer ${token}`
    },
    body: querystring.stringify({ id })
  })
  if (res.status !== 200) {
    return false
  } else {
    return await res.json()
  }
}

const canGetProxy = async (id, actor, token) => {
  const result = await getProxy(id, actor, token)
  return !!result
}

const getAuthCode = async (actor, cookie, scope = 'read write') => {
  const state = crypto.randomBytes(16).toString('hex')
  const authz = actor.endpoints.oauthAuthorizationEndpoint
  const responseType = 'code'
  const codeVerifier = crypto.randomBytes(32).toString('hex')
  const codeChallenge = base64URLEncode(
    crypto.createHash('sha256').update(codeVerifier).digest()
  )
  const qs = querystring.stringify({
    response_type: responseType,
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope,
    state,
    code_challenge_method: 'S256',
    code_challenge: codeChallenge
  })
  const res = await fetch(`${authz}?${qs}`, {
    headers: { Cookie: cookie }
  })
  const body = await res.text()
  const csrfToken = body.match(/name="csrf_token" value="(.+?)"/)[1]
  const res2 = await fetch(authz, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Cookie: cookie
    },
    body: querystring.stringify({
      csrf_token: csrfToken,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope,
      state,
      code_challenge: codeChallenge
    }),
    redirect: 'manual'
  })
  const location = res2.headers.get('Location')
  const locUrl = new URL(location)
  const code = locUrl.searchParams.get('code')
  return [code, codeVerifier]
}

const getTokens = async (actor, code, codeVerifier) => {
  const tokUrl = actor.endpoints.oauthTokenEndpoint
  const res3 = await fetch(tokUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: querystring.stringify({
      grant_type: 'authorization_code',
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier,
      client_id: CLIENT_ID
    })
  })
  const body3 = await res3.json()
  return [body3.access_token, body3.refresh_token]
}

const getAccessToken = async (actor, cookie, scope = 'read write') => {
  const [code, codeVerifier] = await getAuthCode(actor, cookie, scope)
  const [accessToken] = await getTokens(actor, code, codeVerifier)
  return accessToken
}

const base64URLEncode = (str) =>
  str
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')

const cantUpdate = async (actor, token, object, properties) => {
  return failActivity(actor, token, {
    type: 'Update',
    object: { ...object, ...properties }
  })
}

const settle = async (port = MAIN_PORT) => {
  let count = null

  do {
    const res = await fetch(`https://localhost:${port}/queue`)
    count = await res.json()
    if (count > 0) {
      await delay(1)
    }
  } while (count > 0)
}

async function signRequest (keyId, privateKey, method, url, date, digest = null) {
  url = typeof url === 'string' ? new URL(url) : url
  const target =
    url.search && url.search.length
      ? `${url.pathname}?${url.search}`
      : `${url.pathname}`
  let headers = '(request-target) host date'
  let data = `(request-target): ${method.toLowerCase()} ${target}\n`
  data += `host: ${url.host}\n`
  data += `date: ${date}`
  if (digest) {
    data += `\ndigest: ${digest}`
    headers = `${headers} digest`
  }
  const signer = crypto.createSign('sha256')
  signer.update(data)
  const signature = signer.sign(privateKey).toString('base64')
  signer.end()
  const header = `keyId="${keyId}",headers="${headers}",signature="${signature.replace(
    /"/g,
    '\\"'
  )}",algorithm="rsa-sha256"`
  return header
}

describe('onepage.pub', () => {
  let child = null
  let remote = null
  let client = null

  before(async () => {
    child = await startServer(MAIN_PORT)
    remote = await startServer(REMOTE_PORT)
    client = await startClientServer(CLIENT_PORT)
  })

  after(() => {
    child.kill('SIGTERM')
    remote.kill('SIGTERM')
    client.close()
  })

  describe('Root object', () => {
    it('can get the root object', async () => {
      const res = await fetch(`https://localhost:${MAIN_PORT}/`, {
        headers: {
          Accept:
            'application/activity+json,application/ld+json,application/json'
        }
      })
      const obj = await res.json()
      assert.strictEqual(obj.type, 'Service')
      assert.strictEqual(obj.name, 'One Page Pub')
      assert.strictEqual(obj.id, `https://localhost:${MAIN_PORT}/`)
    })
  })

  describe('Registration', () => {
    it('can get a registration form', async () => {
      const res = await fetch(`https://localhost:${MAIN_PORT}/register`)
      const body = await res.text()
      assert.strictEqual(res.status, 200)
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'text/html; charset=utf-8'
      )
      assert(body.includes('<form'))
      assert(body.includes('name="username"'))
      assert(body.includes('name="password"'))
      assert(body.includes('name="confirmation"'))
    })

    it('can register a user', async () => {
      const username = 'testuser1'
      const password = 'testpassword1'
      const res = await fetch(`https://localhost:${MAIN_PORT}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: querystring.stringify({
          username,
          password,
          confirmation: password
        })
      })
      const body = await res.text()
      assert.strictEqual(
        res.status,
        200,
        `Bad status code ${res.status}: ${body}`
      )
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'text/html; charset=utf-8'
      )
      assert(body.includes('Registered'))
      assert(body.includes(username))
      assert(body.match('<span class="token">.+?</span>'))
    })
  })

  describe('Webfinger', () => {
    let username = null
    before(async () => {
      [username] = await registerUser()
    })
    it('can get information about a user', async () => {
      const res = await fetch(
        `https://localhost:${MAIN_PORT}/.well-known/webfinger?resource=acct:${username}@localhost:${MAIN_PORT}`
      )
      assert.strictEqual(res.status, 200)
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'application/jrd+json; charset=utf-8'
      )
      const obj = await res.json()
      assert.strictEqual(
        obj.subject,
        `acct:${username}@localhost:${MAIN_PORT}`
      )
      assert.strictEqual(obj.links[0].rel, 'self')
      assert.strictEqual(obj.links[0].type, 'application/activity+json')
      assert(
        obj.links[0].href.startsWith(`https://localhost:${MAIN_PORT}/person/`)
      )
    })
  })

  describe('Actor endpoint', () => {
    let username = null
    let actorId = null
    let actorRes = null
    let actorBody = null
    let actorObj = null

    before(async () => {
      [username] = await registerUser()
      const res = await fetch(
        `https://localhost:${MAIN_PORT}/.well-known/webfinger?resource=acct:${username}@localhost:${MAIN_PORT}`
      )
      const obj = await res.json()
      actorId = obj.links[0].href
      actorRes = await fetch(actorId)
      actorBody = await actorRes.text()
      actorObj = actorRes.status === 200 ? JSON.parse(actorBody) : null
    })

    it('can fetch the actor endpoint', async () => {
      assert.strictEqual(
        actorRes.status,
        200,
        `Bad status code ${actorRes.status}: ${actorBody}`
      )
      assert.strictEqual(actorRes.headers.get('Content-Type'), AS2_MEDIA_TYPE)
    })

    it('has the as2 @context', () => {
      assert(actorObj['@context'])
      assert.notEqual(-1, actorObj['@context'].indexOf(AS2_CONTEXT))
    })

    it('has the security @context', () => {
      assert(actorObj['@context'])
      assert.notEqual(
        -1,
        actorObj['@context'].indexOf('https://w3id.org/security/v1')
      )
    })

    it('has the blocked @context', () => {
      assert(actorObj['@context'])
      assert(
        actorObj['@context'].includes(
          'https://purl.archive.org/socialweb/blocked'
        )
      )
    })

    it('has the pending @context', () => {
      assert(actorObj['@context'])
      assert(
        actorObj['@context'].includes(
          'https://purl.archive.org/socialweb/pending'
        )
      )
    })

    it('has the correct id', () => {
      assert.strictEqual(actorObj.id, actorId)
    })

    it('has the correct type', () => {
      assert.strictEqual(actorObj.type, 'Person')
    })

    it('has the correct name', () => {
      assert.strictEqual(actorObj.name, username)
    })

    it('has a valid inbox', () => {
      assert.equal('string', typeof actorObj.inbox)
      assert(
        actorObj.inbox.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollection/`
        )
      )
    })

    it('has a valid outbox', () => {
      assert.equal('string', typeof actorObj.outbox)
      assert(
        actorObj.outbox.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollection/`
        )
      )
    })

    it('has a valid followers', () => {
      assert.equal('string', typeof actorObj.followers)
      assert(
        actorObj.followers.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollection/`
        )
      )
    })

    it('has a valid following', () => {
      assert.equal('string', typeof actorObj.following)
      assert(
        actorObj.following.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollection/`
        )
      )
    })

    it('has a valid liked', () => {
      assert.equal('string', typeof actorObj.liked)
      assert(
        actorObj.liked.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollection/`
        )
      )
    })

    it('has a blocked property', () => {
      assert.equal('object', typeof actorObj.blocked)
      assert.equal('string', typeof actorObj.blocked.id)
      assert(
        actorObj.blocked.id.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollection/`
        )
      )
    })

    it('has a pendingFollowers property', () => {
      assert.equal('object', typeof actorObj.pendingFollowers)
      assert.equal('string', typeof actorObj.pendingFollowers.id)
      assert(
        actorObj.pendingFollowers.id.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollection/`
        )
      )
    })

    it('has a pendingFollowing property', () => {
      assert.equal('object', typeof actorObj.pendingFollowing)
      assert.equal('string', typeof actorObj.pendingFollowing.id)
      assert(
        actorObj.pendingFollowing.id.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollection/`
        )
      )
    })

    it('has a public key', () => {
      assert(actorObj.publicKey)
      assert.equal('object', typeof actorObj.publicKey)
      assert.equal('string', typeof actorObj.publicKey.id)
      assert(
        actorObj.publicKey.id.startsWith(`https://localhost:${MAIN_PORT}/cryptographickey/`)
      )
      assert.equal('string', typeof actorObj.publicKey.type)
      assert.equal('CryptographicKey', actorObj.publicKey.type)
      assert.equal('string', typeof actorObj.publicKey.owner)
      assert.equal(actorObj.publicKey.owner, actorId)
    })

    it('has an endpoints property', () => {
      assert(actorObj.endpoints)
      assert.equal('object', typeof actorObj.endpoints)
    })

    it('has an proxyUrl endpoint', () => {
      assert(actorObj.endpoints)
      assert.equal('object', typeof actorObj.endpoints)
      assert.equal('string', typeof actorObj.endpoints.proxyUrl)
    })
  })

  describe('Actor streams', () => {
    let actor = null
    let token = null
    let token2 = null
    before(async () => {
      [actor, token] = await registerActor();
      [, token2] = await registerActor()
    })
    it('can get actor inbox', async () => {
      const res = await fetch(actor.inbox)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(res.headers.get('Content-Type'), AS2_MEDIA_TYPE)
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.inbox)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollectionpage/`
        )
      )
    })
    it('can get actor outbox', async () => {
      const res = await fetch(actor.outbox)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(res.headers.get('Content-Type'), AS2_MEDIA_TYPE)
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.outbox)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollectionpage/`
        )
      )
    })
    it('can get actor followers', async () => {
      const res = await fetch(actor.followers)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(res.headers.get('Content-Type'), AS2_MEDIA_TYPE)
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.followers)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollectionpage/`
        )
      )
    })
    it('can get actor following', async () => {
      const res = await fetch(actor.following)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(res.headers.get('Content-Type'), AS2_MEDIA_TYPE)
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.following)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollectionpage/`
        )
      )
    })
    it('can get actor liked', async () => {
      const res = await fetch(actor.liked)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(res.headers.get('Content-Type'), AS2_MEDIA_TYPE)
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.liked)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollectionpage/`
        )
      )
    })

    it('cannot get actor blocked without authentication', async () => {
      const res = await fetch(actor.blocked.id)
      assert.strictEqual(res.status, 401)
    })

    it('cannot get actor blocked with other user authentication', async () => {
      const res = await fetch(actor.blocked.id, {
        headers: {
          Authorization: `Bearer ${token2}`
        }
      })
      assert.strictEqual(res.status, 403)
    })

    it('can get actor blocked with authentication', async () => {
      const res = await fetch(actor.blocked.id, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      })
      assert.strictEqual(res.status, 200)
      assert.strictEqual(res.headers.get('Content-Type'), AS2_MEDIA_TYPE)
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.blocked.id)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollectionpage/`
        )
      )
    })

    it('cannot get actor pendingFollowers without authentication', async () => {
      const res = await fetch(actor.pendingFollowers.id)
      assert.strictEqual(res.status, 401)
    })

    it('cannot get actor pendingFollowers with other user authentication', async () => {
      const res = await fetch(actor.pendingFollowers.id, {
        headers: {
          Authorization: `Bearer ${token2}`
        }
      })
      assert.strictEqual(res.status, 403)
    })

    it('can get actor pendingFollowers', async () => {
      const res = await fetch(actor.pendingFollowers.id, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      })
      assert.strictEqual(res.status, 200)
      assert.strictEqual(res.headers.get('Content-Type'), AS2_MEDIA_TYPE)
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.pendingFollowers.id)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollectionpage/`
        )
      )
    })

    it('cannot get actor pendingFollowing without authentication', async () => {
      const res = await fetch(actor.pendingFollowing.id)
      assert.strictEqual(res.status, 401)
    })

    it('cannot get actor pendingFollowing with other user authentication', async () => {
      const res = await fetch(actor.pendingFollowing.id, {
        headers: {
          Authorization: `Bearer ${token2}`
        }
      })
      assert.strictEqual(res.status, 403)
    })

    it('can get actor pendingFollowing', async () => {
      const res = await fetch(actor.pendingFollowing.id, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      })
      assert.strictEqual(res.status, 200)
      assert.strictEqual(res.headers.get('Content-Type'), AS2_MEDIA_TYPE)
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.pendingFollowing.id)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith(
          `https://localhost:${MAIN_PORT}/orderedcollectionpage/`
        )
      )
    })
  })

  describe('Post to outbox', () => {
    let actor = null
    let token = null
    let res = null
    let body = null
    let obj = null

    const activity = {
      '@context': AS2_CONTEXT,
      type: 'IntransitiveActivity',
      to: PUBLIC
    }

    before(async () => {
      [actor, token] = await registerActor()
      res = await fetch(actor.outbox, {
        method: 'POST',
        headers: {
          'Content-Type': AS2_MEDIA_TYPE,
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(activity)
      })
      body = await res.text()
      obj = JSON.parse(body)
    })
    it('has the correct HTTP response', async () => {
      assert.strictEqual(
        res.status,
        201,
        `Bad status code ${res.status}: ${body}`
      )
      assert.strictEqual(res.headers.get('Content-Type'), AS2_MEDIA_TYPE)
    })

    it('has an object id', async () => {
      assert(obj.id)
    })

    it('has the correct object type', async () => {
      assert.strictEqual(obj.type, activity.type)
    })

    it('has the correct addressees', async () => {
      assert.strictEqual(obj.to.id, activity.to)
    })

    it("appears in the actor's inbox", async () => {
      const inbox = await (await fetch(actor.inbox)).json()
      const inboxPage = await (await fetch(inbox.first.id)).json()
      assert(inboxPage.orderedItems.some((act) => act.id === obj.id))
    })

    it("appears in the actor's outbox", async () => {
      const outbox = await (await fetch(actor.outbox)).json()
      const outboxPage = await (await fetch(outbox.first.id)).json()
      assert(outboxPage.orderedItems.some((act) => act.id === obj.id))
    })
  })

  describe('Post to outbox with application/ld+json', () => {
    let actor = null
    let token = null
    let res = null
    let body = null
    let obj = null

    const activity = {
      '@context': AS2_CONTEXT,
      type: 'IntransitiveActivity',
      to: PUBLIC
    }

    before(async () => {
      [actor, token] = await registerActor()
      res = await fetch(actor.outbox, {
        method: 'POST',
        headers: {
          'Content-Type':
            'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
          Authorization: `Bearer ${token}`
        },
        body: JSON.stringify(activity)
      })
      body = await res.text()
      obj = JSON.parse(body)
    })
    it('has the correct HTTP response', async () => {
      assert.strictEqual(
        res.status,
        201,
        `Bad status code ${res.status}: ${body}`
      )
      assert.strictEqual(res.headers.get('Content-Type'), AS2_MEDIA_TYPE)
    })

    it('has an object id', async () => {
      assert(obj.id)
    })

    it('has the correct object type', async () => {
      assert.strictEqual(obj.type, activity.type)
    })

    it('has the correct addressees', async () => {
      assert.strictEqual(obj.to?.id, activity.to)
    })

    it("appears in the actor's inbox", async () => {
      const inbox = await (await fetch(actor.inbox)).json()
      const inboxPage = await (await fetch(inbox.first.id)).json()
      assert(inboxPage.orderedItems.some((act) => act.id === obj.id))
    })

    it("appears in the actor's outbox", async () => {
      const outbox = await (await fetch(actor.outbox)).json()
      const outboxPage = await (await fetch(outbox.first.id)).json()
      assert(outboxPage.orderedItems.some((act) => act.id === obj.id))
    })
  })

  describe('Filter collections', () => {
    let actor1 = null
    let token1 = null
    let token2 = null
    let activity = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [, token2] = await registerActor()
      const input = {
        '@context': AS2_CONTEXT,
        type: 'IntransitiveActivity',
        to: [actor1.id]
      }
      const res = await fetch(actor1.outbox, {
        method: 'POST',
        headers: {
          'Content-Type':
            'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
          Authorization: `Bearer ${token1}`
        },
        body: JSON.stringify(input)
      })
      const body = await res.text()
      activity = JSON.parse(body)
    })

    it('author can see own private activity', async () => {
      const outbox = await (
        await fetch(actor1.outbox, {
          headers: {
            Authorization: `Bearer ${token1}`
          }
        })
      ).json()
      const outboxPage = await (
        await fetch(outbox.first.id, {
          headers: {
            Authorization: `Bearer ${token1}`
          }
        })
      ).json()
      assert(outboxPage.orderedItems.some((val) => val.id === activity.id))
    })

    it('others cannot see a private activity', async () => {
      const outbox = await (
        await fetch(actor1.outbox, {
          headers: {
            Authorization: `Bearer ${token2}`
          }
        })
      ).json()
      const outboxPage = await (
        await fetch(outbox.first.id, {
          headers: {
            Authorization: `Bearer ${token2}`
          }
        })
      ).json()
      assert(outboxPage.orderedItems.every((val) => val.id !== activity.id))
    })
  })

  describe('Remote delivery', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null

    before(async () => {
      [actor1, token1] = await registerActor(MAIN_PORT);
      [actor2, token2] = await registerActor(REMOTE_PORT)
    })

    it('sends to remote addressees', async () => {
      const activity = {
        '@context': AS2_CONTEXT,
        type: 'IntransitiveActivity',
        to: actor2.id
      }
      const res = await fetch(actor1.outbox, {
        method: 'POST',
        headers: {
          'Content-Type':
            'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
          Authorization: `Bearer ${token1}`
        },
        body: JSON.stringify(activity)
      })
      const body = await res.text()
      const obj = JSON.parse(body)
      await settle(MAIN_PORT)
      const inbox = await (
        await fetch(actor2.inbox, {
          headers: { Authorization: `Bearer ${token2}` }
        })
      ).json()
      const inboxPage = await (
        await fetch(inbox.first.id, {
          headers: { Authorization: `Bearer ${token2}` }
        })
      ).json()
      assert(inboxPage.orderedItems.some((act) => act.id === obj.id))
    })

    it('receives from remote senders', async () => {
      const activity = {
        '@context': AS2_CONTEXT,
        type: 'IntransitiveActivity',
        to: actor1.id
      }
      const res = await fetch(actor2.outbox, {
        method: 'POST',
        headers: {
          'Content-Type':
            'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
          Authorization: `Bearer ${token2}`
        },
        body: JSON.stringify(activity)
      })
      const body = await res.text()
      const obj = JSON.parse(body)
      // Wait for delivery!
      await settle(REMOTE_PORT)
      const inbox = await (
        await fetch(actor1.inbox, {
          headers: { Authorization: `Bearer ${token1}` }
        })
      ).json()
      const inboxPage = await (
        await fetch(inbox.first.id, {
          headers: { Authorization: `Bearer ${token1}` }
        })
      ).json()
      assert(inboxPage.orderedItems.some((act) => act.id === obj.id))
    })
  })

  describe('Follow Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let follow = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor()
      follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
    })

    it('has an id', () => {
      assert(follow.id)
    })

    it('has the right object', () => {
      assert.strictEqual(follow.object.id, actor2.id)
    })

    it('has the right type', () => {
      assert.strictEqual(follow.type, 'Follow')
    })

    it("appears in the actor's pending following", async () => {
      assert(await isInStream(actor1.pendingFollowing, follow, token1))
    })

    it("appears in the other's pending followers", async () => {
      assert(await isInStream(actor2.pendingFollowers, follow, token2))
    })

    it("does not put the actor in the other's followers", async () => {
      assert(!(await isInStream(actor2.followers, actor1, token2)))
    })

    it("does not put the other in the actor's following", async () => {
      assert(!(await isInStream(actor1.following, actor2, token1)))
    })
  })

  describe('Accept Follow Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let follow = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor()
      follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await settle(MAIN_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await settle(MAIN_PORT)
    })

    it("puts the actor in the other's followers", async () => {
      assert(await isInStream(actor2.followers, actor1, token2))
    })

    it("puts the other in the actor's following", async () => {
      assert(await isInStream(actor1.following, actor2, token1))
    })

    it('distributes to the actor when the other posts to followers', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor2.followers,
        type: 'Note',
        contentMap: {
          en: 'Hello, world!'
        }
      })
      await settle(MAIN_PORT)
      assert(await isInStream(actor1.inbox, createNote, token1))
    })

    it('distributes to the actor when the other posts to public', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: PUBLIC,
        type: 'Note',
        contentMap: {
          en: 'Hello, world!'
        }
      })
      await settle(MAIN_PORT)
      assert(await isInStream(actor1.inbox, createNote, token1))
    })
  })

  describe('Reject Follow Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let follow = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor()
      follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        type: 'Reject',
        object: follow.id
      })
    })

    it("does not appear in the actor's pending following", async () => {
      assert(!(await isInStream(actor1.pendingFollowing, follow, token1)))
    })

    it("does not appear in the other's pending followers", async () => {
      assert(!(await isInStream(actor2.pendingFollowers, follow, token2)))
    })

    it("does not put the actor in the other's followers", async () => {
      assert(!(await isInStream(actor2.followers, actor1, token2)))
    })

    it("does not put the other in the actor's following", async () => {
      assert(!(await isInStream(actor1.following, actor2, token1)))
    })

    it('does not distribute to the actor when the other posts to followers', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor2.followers,
        type: 'Note',
        contentMap: {
          en: 'Hello, world!'
        }
      })
      assert(!(await isInStream(actor1.inbox, createNote, token1)))
    })

    it('does not distribute to the actor when the other posts to public', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: PUBLIC,
        type: 'Note',
        contentMap: {
          en: 'Hello, world!'
        }
      })
      assert(!(await isInStream(actor1.inbox, createNote, token1)))
    })
  })

  describe('Create Activity', () => {
    let actor1 = null
    let token1 = null
    let activity = null
    const content = 'My dog has fleas.'
    before(async () => {
      [actor1, token1] = await registerActor()
      const source = {
        '@context': AS2_CONTEXT,
        type: 'Create',
        object: {
          type: 'Note',
          content
        }
      }
      const res = await fetch(actor1.outbox, {
        method: 'POST',
        headers: {
          'Content-Type':
            'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
          Authorization: `Bearer ${token1}`
        },
        body: JSON.stringify(source)
      })
      const body = await res.text()
      activity = JSON.parse(body)
    })
    it('has a new object ID', async () => {
      assert.equal('object', typeof activity.object)
      assert.equal('string', typeof activity.object.id)
    })
    it('can fetch the new note', async () => {
      assert.equal('object', typeof activity.object)
      assert.equal('string', typeof activity.object.id)
      const res = await fetch(activity.object.id, {
        headers: {
          Authorization: `Bearer ${token1}`
        }
      })
      assert.equal(200, res.status)
      const fetched = await res.json()
      assert.equal(activity.object?.id, fetched.id)
      assert.equal('Note', fetched.type)
      assert.equal(content, fetched.content)
      assert.equal('string', typeof fetched.published)
      assert.equal('string', typeof fetched.updated)
    })
  })

  describe('Update Activity', () => {
    let actor1 = null
    let token1 = null
    let created = null
    let updated = null
    const content = 'My dog has fleas.'
    const contentMap = {
      en: content,
      fr: 'Mon chien a des puces.'
    }
    before(async () => {
      [actor1, token1] = await registerActor()
      const source = {
        '@context': AS2_CONTEXT,
        type: 'Create',
        object: {
          type: 'Note',
          content
        }
      }
      const res = await fetch(actor1.outbox, {
        method: 'POST',
        headers: {
          'Content-Type':
            'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
          Authorization: `Bearer ${token1}`
        },
        body: JSON.stringify(source)
      })
      created = await res.json()
    })
    it('can update the note', async () => {
      const updateSource = {
        '@context': AS2_CONTEXT,
        type: 'Update',
        object: {
          id: created.object.id,
          content: null,
          contentMap
        }
      }
      const updateRes = await fetch(actor1.outbox, {
        method: 'POST',
        headers: {
          'Content-Type':
            'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
          Authorization: `Bearer ${token1}`
        },
        body: JSON.stringify(updateSource)
      })
      const updateBody = await updateRes.text()
      assert.equal(
        201,
        updateRes.status,
        `Bad status code ${updateRes.status} ${updateBody}`
      )
      updated = JSON.parse(updateBody)
      assert.ok(updated.id)
      assert.equal('Update', updated.type)
      assert.ok(updated.object)
    })
    it('has the same object id', async () => {
      assert.equal(created.object.id, updated.object.id)
    })
    it('has the previous type', async () => {
      assert.equal('Note', updated.object.type)
    })
    it('has the new property', async () => {
      assert('contentMap' in updated.object)
      assert.equal(contentMap.en, updated.object?.contentMap?.en)
      assert.equal(contentMap.fr, updated.object?.contentMap?.fr)
    })
    it("doesn't have the old property", async () => {
      assert(!('content' in updated.object))
    })
    it('has the same published property', async () => {
      assert.equal(updated.object.published, created.object.published)
    })
    it('has a new updated property', async () => {
      assert.notEqual(updated.object.updated, created.object.updated)
    })
    it('can fetch the updated note', async () => {
      const res = await fetch(updated.object.id, {
        headers: { Authorization: `Bearer ${token1}` }
      })
      const fetched = await res.json()
      assert.equal(updated.object.id, fetched.id)
      assert.equal('Note', fetched.type)
      assert.equal(contentMap.en, fetched.contentMap.en)
      assert.equal(contentMap.fr, fetched.contentMap.fr)
      assert(!('content' in fetched))
    })
  })

  describe('Delete Activity', () => {
    let actor1 = null
    let token1 = null
    let created = null
    let deleted = null
    before(async () => {
      [actor1, token1] = await registerActor()
      const source = {
        '@context': AS2_CONTEXT,
        type: 'Create',
        object: {
          type: 'Note',
          content: 'My dog has fleas.'
        }
      }
      const res = await fetch(actor1.outbox, {
        method: 'POST',
        headers: {
          'Content-Type':
            'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
          Authorization: `Bearer ${token1}`
        },
        body: JSON.stringify(source)
      })
      created = await res.json()
      const deleteSource = {
        '@context': AS2_CONTEXT,
        type: 'Delete',
        object: created.object.id
      }
      const deleteRes = await fetch(actor1.outbox, {
        method: 'POST',
        headers: {
          'Content-Type':
            'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
          Authorization: `Bearer ${token1}`
        },
        body: JSON.stringify(deleteSource)
      })
      deleted = await deleteRes.json()
    })
    it('has the same object id', async () => {
      assert.equal(created.object.id, deleted.object.id)
    })
    it('is a Tombstone', async () => {
      assert.equal('Tombstone', deleted.object.type)
    })
    it('has a summaryMap property', async () => {
      assert(deleted.object?.summaryMap?.en)
    })
    it('can fetch the Tombstone', async () => {
      const res = await fetch(deleted.object.id, {
        headers: { Authorization: `Bearer ${token1}` }
      })
      assert.equal(410, res.status)
      const fetched = await res.json()
      assert.equal(deleted.object.id, fetched.id)
      assert.equal('Tombstone', fetched.type)
      assert.equal('Note', fetched.formerType)
      assert(fetched.deleted)
      assert(fetched.updated)
      assert(fetched.published)
      assert(fetched.summaryMap?.en)
    })
  })

  describe('Add Activity', () => {
    let actor1 = null
    let token1 = null
    let createdCollection = null
    let createdNote = null
    before(async () => {
      [actor1, token1] = await registerActor()
      createdNote = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Buy some milk'
          }
        }
      })
      createdCollection = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        type: 'Create',
        object: {
          type: 'Collection',
          nameMap: {
            en: 'TODO list'
          },
          items: []
        }
      })
      await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        type: 'Add',
        object: createdNote.object.id,
        target: createdCollection.object.id
      })
    })
    it('adds an object to a collection', async () => {
      const res = await fetch(createdCollection.object.id, {
        headers: { Authorization: `Bearer ${token1}` }
      })
      const fetched = await res.json()
      assert(fetched.items.some((item) => item.id === createdNote.object.id))
    })
  })

  describe('Remove Activity', () => {
    let actor1 = null
    let token1 = null
    let createdCollection = null
    let createdNote1 = null
    let createdNote2 = null
    before(async () => {
      [actor1, token1] = await registerActor()
      createdNote1 = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Buy some milk'
          }
        }
      })
      createdNote2 = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Clean the garage'
          }
        }
      })
      createdCollection = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        type: 'Create',
        object: {
          type: 'Collection',
          nameMap: {
            en: 'TODO list'
          },
          items: []
        }
      })
      await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        type: 'Add',
        object: createdNote1.object.id,
        target: createdCollection.object.id
      })
      await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        type: 'Add',
        object: createdNote2.object.id,
        target: createdCollection.object.id
      })
      await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        type: 'Remove',
        object: createdNote1.object.id,
        target: createdCollection.object.id
      })
    })
    it('removes an object from a collection', async () => {
      const res = await fetch(createdCollection.object.id, {
        headers: { Authorization: `Bearer ${token1}` }
      })
      const fetched = await res.json()
      assert(fetched.items.every((item) => item.id !== createdNote1.object.id))
    })
    it('leaves other objects in the collection', async () => {
      const res = await fetch(createdCollection.object.id, {
        headers: { Authorization: `Bearer ${token1}` }
      })
      const fetched = await res.json()
      assert(fetched.items.some((item) => item.id === createdNote2.object.id))
    })
  })

  describe('Like Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let createdNote1 = null
    let liked = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor()
      createdNote1 = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'My dog has fleas.'
          }
        }
      })
      liked = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Like',
        object: createdNote1.object.id
      })
    })

    it("appears in the object's likes", async () => {
      const note1 = await (await fetch(createdNote1.object.id)).json()
      const likes = await (await fetch(note1.likes.id)).json()
      const likesPage = await (await fetch(likes.first.id)).json()
      assert(
        likesPage.orderedItems.some((activity) => activity.id === liked.id)
      )
    })

    it("object's likes count is 1", async () => {
      const note1 = await (await fetch(createdNote1.object.id)).json()
      const likes = await (await fetch(note1.likes.id)).json()
      assert.equal(likes.totalItems, 1)
    })

    it("appears in the liking actor's liked stream", async () => {
      const likedStream = await (await fetch(actor2.liked)).json()
      const likedPage = await (await fetch(likedStream.first.id)).json()
      assert(
        likedPage.orderedItems.some((obj) => obj.id === createdNote1.object.id)
      )
    })

    it("actor's liked count is 1", async () => {
      const likedStream = await (await fetch(actor2.liked)).json()
      assert.equal(likedStream.totalItems, 1)
    })
  })

  describe('Block Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor()
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        type: 'Follow',
        object: actor1.id
      })
      await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [actor2.id],
        type: 'Block',
        object: actor2.id
      })
    })

    it("other appears in the actor's blocked", async () => {
      const blockedStream = await (
        await fetch(actor1.blocked.id, {
          headers: { Authorization: `Bearer ${token1}` }
        })
      ).json()
      const blockedPage = await (
        await fetch(blockedStream.first.id, {
          headers: { Authorization: `Bearer ${token1}` }
        })
      ).json()
      assert(blockedPage.orderedItems.some((actor) => actor.id === actor2.id))
    })

    it("other does not appear in the actor's followers", async () => {
      const followersStream = await (await fetch(actor1.followers)).json()
      const followersPage = await (
        await fetch(followersStream.first.id)
      ).json()
      assert(
        followersPage.orderedItems.every((actor) => actor.id !== actor2.id)
      )
    })

    it("actor does not appear in the other's following", async () => {
      const followingStream = await (await fetch(actor2.following)).json()
      const followingPage = await (
        await fetch(followingStream.first.id)
      ).json()
      assert(
        followingPage.orderedItems.every((actor) => actor.id !== actor1.id)
      )
    })

    it("other can't send to actor", async () => {
      const created = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor1.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello there.'
          }
        }
      })
      const inboxStream = await (
        await fetch(actor1.inbox, {
          headers: { Authorization: `Bearer ${token1}` }
        })
      ).json()
      const inboxPage = await (
        await fetch(inboxStream.first.id, {
          headers: { Authorization: `Bearer ${token1}` }
        })
      ).json()
      assert(
        inboxPage.orderedItems.every((obj) => obj.id !== created.object.id)
      )
    })

    it("other can't like actor note", async () => {
      const created1 = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: PUBLIC,
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Here are my thoughts.'
          }
        }
      })
      const res = await fetch(actor2.outbox, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token2}`,
          'Content-Type':
            'application/ld+json; profile="https://www.w3.org/ns/activitystreams"'
        },
        body: JSON.stringify({
          '@context': AS2_CONTEXT,
          to: PUBLIC,
          type: 'Like',
          object: created1.object.id
        })
      })
      assert.strictEqual(res.status, 400)
    })

    it("other can't read actor profile", async () => {
      const res = await fetch(actor1.id, {
        headers: { Authorization: `Bearer ${token2}` }
      })
      assert.strictEqual(res.status, 403)
    })

    it("other can't read actor outbox", async () => {
      const res = await fetch(actor1.outbox, {
        headers: { Authorization: `Bearer ${token2}` }
      })
      assert.strictEqual(res.status, 403)
    })

    it("other can't read actor note", async () => {
      const created = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: PUBLIC,
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello there.'
          }
        }
      })
      const res = await fetch(created.object.id, {
        headers: { Authorization: `Bearer ${token2}` }
      })
      assert.strictEqual(res.status, 403)
    })
  })

  describe('replies collection', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let createNote = null
    let createReply = null

    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor()
      createNote = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello world!'
          }
        }
      })
      createReply = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          inReplyTo: createNote.object.id,
          type: 'Note',
          contentMap: {
            en: 'Hello back!'
          }
        }
      })
    })

    it("reply appears in original's replies", async () => {
      const repliesStream = await (
        await fetch(createNote.object.replies.id, {
          headers: { Authorization: `Bearer ${token1}` }
        })
      ).json()
      const repliesPage = await (
        await fetch(repliesStream.first.id, {
          headers: { Authorization: `Bearer ${token1}` }
        })
      ).json()
      assert(
        repliesPage.orderedItems.some(
          (reply) => reply.id === createReply.object.id
        )
      )
    })
  })

  describe('Announce activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let createNote = null
    let announce = null

    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor()
      createNote = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello world!'
          }
        }
      })
      announce = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Announce',
        object: createNote.object.id
      })
    })

    it("Announce appears in original's shares", async () => {
      const sharesStream = await (
        await fetch(createNote.object.shares.id, {
          headers: { Authorization: `Bearer ${token1}` }
        })
      ).json()
      const sharesPage = await (
        await fetch(sharesStream.first.id, {
          headers: { Authorization: `Bearer ${token1}` }
        })
      ).json()
      assert(sharesPage.orderedItems.some((share) => share.id === announce.id))
    })
  })

  describe('Undo Like activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let createNote = null
    let like = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor()
      createNote = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello world!'
          }
        }
      })
      like = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Like',
        object: createNote.object.id
      })
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Undo',
        object: like.id
      })
    })

    it("object is not in actor's liked", async () => {
      const likedStream = await (
        await fetch(actor2.liked, {
          headers: { Authorization: `Bearer ${token2}` }
        })
      ).json()
      const likedPage = await (
        await fetch(likedStream.first.id, {
          headers: { Authorization: `Bearer ${token2}` }
        })
      ).json()
      assert(
        likedPage.orderedItems.every((obj) => obj.id !== createNote.object.id)
      )
    })

    it("like activity is not in object's likes", async () => {
      const likesStream = await (
        await fetch(createNote.object.likes.id, {
          headers: { Authorization: `Bearer ${token1}` }
        })
      ).json()
      const likesPage = await (
        await fetch(likesStream.first.id, {
          headers: { Authorization: `Bearer ${token1}` }
        })
      ).json()
      assert(likesPage.orderedItems.every((act) => act.id !== like.id))
    })
  })

  describe('Undo Block activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let block = null
    let createNote = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor()
      block = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Block',
        object: actor2.id
      })
      createNote = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello world!'
          }
        }
      })
      await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Undo',
        object: block.id
      })
    })

    it("other is not in actor's blocked", async () => {
      const actorInBlocked = await isInStream(actor1.blocked, actor2, token1)
      assert(!actorInBlocked)
    })

    it('other can fetch actor content', async () => {
      const note = await fetch(createNote.object.id, {
        headers: { Authorization: `Bearer ${token2}` }
      })
      assert(note.ok)
    })

    it('other can fetch actor profile', async () => {
      const profile = await fetch(actor1.id, {
        headers: { Authorization: `Bearer ${token2}` }
      })
      assert(profile.ok)
    })

    it('other can follow actor', async () => {
      const follow = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        type: 'Follow',
        object: actor1.id
      })
      assert(follow.id)
    })

    it('other can reply to actor', async () => {
      const reply = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        type: 'Create',
        object: {
          inReplyTo: createNote.object.id,
          type: 'Note',
          contentMap: {
            en: 'Hello back!'
          }
        }
      })
      assert(reply.id)
    })
  })

  describe('Undo Follow activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let follow = null

    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor()
      follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Undo',
        object: follow.id
      })
    })

    it("other is not in actor's following", async () => {
      assert(!(await isInStream(actor1.following, actor2)))
    })

    it("actor is not in other's followers", async () => {
      assert(!(await isInStream(actor2.followers, actor1)))
    })

    it('actor does not receive public posts', async () => {
      const createPublic = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello world!'
          }
        }
      })
      await settle(REMOTE_PORT)
      assert(!(await isInStream(actor1.inbox, createPublic, token1)))
    })

    it('actor does not receive followers-only posts', async () => {
      const createFollowersOnly = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor2.followers],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello world!'
          }
        }
      })
      await settle(REMOTE_PORT)
      assert(!(await isInStream(actor1.inbox, createFollowersOnly, token1)))
    })
  })

  describe('Undo pending Follow activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let follow = null

    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor()
      follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Undo',
        object: follow.id
      })
    })

    it("other is not in actor's pendingFollowing", async () => {
      assert(!(await isInStream(actor1.pendingFollowing, follow, token1)))
    })

    it("actor is not in other's pendingFollowers", async () => {
      assert(!(await isInStream(actor2.pendingFollowers, follow, token2)))
    })
  })

  describe('Remote Follow Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let follow = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT)
      follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await settle(MAIN_PORT)
      await settle(REMOTE_PORT)
    })

    it("appears in the actor's pending following", async () => {
      assert(await isInStream(actor1.pendingFollowing, follow, token1))
    })

    it("appears in the other's pending followers", async () => {
      assert(await isInStream(actor2.pendingFollowers, follow, token2))
    })

    it("does not put the actor in the other's followers", async () => {
      assert(!(await isInStream(actor2.followers, actor1, token2)))
    })

    it("does not put the other in the actor's following", async () => {
      assert(!(await isInStream(actor1.following, actor2, token1)))
    })
  })

  describe('Remote Accept Follow Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let follow = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT)
      follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await settle(MAIN_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await settle(REMOTE_PORT)
    })

    it("removes the follow from the actor's pending following", async () => {
      assert(!(await isInStream(actor1.pendingFollowing, follow, token1)))
    })

    it("removes the follow from the other's pending followers", async () => {
      assert(!(await isInStream(actor2.pendingFollowers, follow, token2)))
    })

    it("puts the actor in the other's followers", async () => {
      assert(await isInStream(actor2.followers, actor1, token2))
    })

    it("puts the other in the actor's following", async () => {
      assert(await isInStream(actor1.following, actor2, token1))
    })

    it('distributes to the actor when the other posts to followers', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor2.followers,
        type: 'Note',
        contentMap: {
          en: 'Hello, world!'
        }
      })
      await settle(REMOTE_PORT)
      assert(await isInStream(actor1.inbox, createNote, token1))
    })

    it('distributes to the actor when the other posts to public', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: PUBLIC,
        type: 'Note',
        contentMap: {
          en: 'Hello, world!'
        }
      })
      await settle(REMOTE_PORT)
      assert(await isInStream(actor1.inbox, createNote, token1))
    })
  })

  describe('Remote Reject Follow Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let follow = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT)
      follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await settle(MAIN_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor1.id,
        type: 'Reject',
        object: follow.id
      })
      await settle(REMOTE_PORT)
    })

    it("does not appear in the actor's pending following", async () => {
      assert(!(await isInStream(actor1.pendingFollowing, follow, token1)))
    })

    it("does not appear in the other's pending followers", async () => {
      assert(!(await isInStream(actor2.pendingFollowers, follow, token2)))
    })

    it("does not put the actor in the other's followers", async () => {
      assert(!(await isInStream(actor2.followers, actor1, token2)))
    })

    it("does not put the other in the actor's following", async () => {
      assert(!(await isInStream(actor1.following, actor2, token1)))
    })

    it('does not distribute to the actor when the other posts to followers', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor2.followers,
        type: 'Note',
        contentMap: {
          en: 'Hello, world!'
        }
      })
      await settle(REMOTE_PORT)
      assert(!(await isInStream(actor1.inbox, createNote, token1)))
    })

    it('does not distribute to the actor when the other posts to public', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: PUBLIC,
        type: 'Note',
        contentMap: {
          en: 'Hello, world!'
        }
      })
      await settle(REMOTE_PORT)
      assert(!(await isInStream(actor1.inbox, createNote, token1)))
    })
  })

  describe('Proxy URL', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let actor3 = null
    let token3 = null
    let follow = null
    let pub = null
    let priv = null
    let followers = null
    let self = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT);
      [actor3, token3] = await registerActor()
      follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await settle(MAIN_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await settle(REMOTE_PORT)
      pub = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      priv = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor1.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: `Hello, ${actor1.name}!`
          }
        }
      })
      followers = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor2.followers],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, followers!'
          }
        }
      })
      self = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor2.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, self!'
          }
        }
      })
      await settle(REMOTE_PORT)
    })

    it('follower can get public note through proxy', async () => {
      assert(await canGetProxy(pub.object.id, actor1, token1))
    })

    it('follower can get private note through proxy', async () => {
      assert(await canGetProxy(priv.object.id, actor1, token1))
    })

    it('follower can get followers-only note through proxy', async () => {
      assert(await canGetProxy(followers.object.id, actor1, token1))
    })

    it('follower cannot get self-only note through proxy', async () => {
      assert(!(await canGetProxy(self.object.id, actor1, token1)))
    })

    it('random can get public note through proxy', async () => {
      assert(await canGetProxy(pub.object.id, actor3, token3))
    })

    it('random cannot get private note through proxy', async () => {
      assert(!(await canGetProxy(priv.object.id, actor3, token3)))
    })

    it('random cannot get followers-only note through proxy', async () => {
      assert(!(await canGetProxy(followers.object.id, actor3, token3)))
    })

    it('random cannot get self-only note through proxy', async () => {
      assert(!(await canGetProxy(self.object.id, actor3, token3)))
    })
  })

  describe('Remote Create Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let follow = null
    let createNote = null
    let createReply = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT)
      follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await settle(MAIN_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await settle(REMOTE_PORT)
      createNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor2.followers],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await settle(REMOTE_PORT)
      createReply = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [actor2.id, actor2.followers],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, back!'
          },
          inReplyTo: createNote.object.id
        }
      })
      await settle(MAIN_PORT)
    })

    it("note appears in the actor's inbox", async () => {
      assert(await isInStream(actor1.inbox, createNote, token1))
    })

    it("reply appears in other's inbox", async () => {
      assert(await isInStream(actor2.inbox, createReply, token2))
    })

    it("reply appears in original note's replies", async () => {
      assert(
        await isInStream(createNote.object.replies, createReply.object, token2)
      )
    })
  })

  describe('Remote Update Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let follow = null
    let createNote = null
    let updateNote = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT)
      follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await settle(MAIN_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await settle(REMOTE_PORT)
      createNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await settle(REMOTE_PORT)
      updateNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Update',
        object: {
          id: createNote.object.id,
          contentMap: {
            en: 'Hello, world! (updated)'
          }
        }
      })
      await settle(REMOTE_PORT)
    })

    it('correct value in proxy', async () => {
      const note = await getProxy(createNote.object.id, actor1, token1)
      assert.equal(note.contentMap.en, 'Hello, world! (updated)')
    })

    it('correct value for update in inbox', async () => {
      const activities = await getMembers(actor1.inbox, token1)
      const update = activities.find((a) => a.id === updateNote.id)
      assert.strictEqual(
        update.object?.contentMap?.en,
        'Hello, world! (updated)'
      )
    })

    it('correct value for create in inbox', async () => {
      const activities = await getMembers(actor1.inbox, token1)
      const create = activities.find((a) => a.id === createNote.id)
      assert.strictEqual(
        create.object?.contentMap?.en,
        'Hello, world! (updated)'
      )
    })
  })

  describe('Remote Delete Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let createNote = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT)
      const follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await settle(MAIN_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await settle(REMOTE_PORT)
      createNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await settle(REMOTE_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Delete',
        object: createNote.object.id
      })
      await settle(REMOTE_PORT)
    })

    it('correct value in proxy', async () => {
      const res = await fetch(actor1.endpoints.proxyUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Bearer ${token1}`
        },
        body: querystring.stringify({ id: createNote.object.id })
      })
      assert.strictEqual(res.status, 410)
      const ts = await res.json()
      assert.strictEqual(ts.type, 'Tombstone')
    })

    it('correct value for create in inbox', async () => {
      const activities = await getMembers(actor1.inbox, token1)
      const create = activities.find((a) => a.id === createNote.id)
      assert.strictEqual(create.object?.type, 'Tombstone')
    })
  })

  describe('Remote Like Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let createNote = null
    let like = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT)
      const follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await settle(MAIN_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await settle(REMOTE_PORT)
      createNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await settle(REMOTE_PORT)
      like = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [actor2.id, PUBLIC],
        type: 'Like',
        object: createNote.object.id
      })
      await settle(MAIN_PORT)
    })

    it('like is in the likes collection', async () => {
      assert(await isInStream(createNote.object.likes, like, token2))
    })

    it('likes total count is correct', async () => {
      const likes = await getObject(createNote.object.likes.id, token2)
      assert.strictEqual(likes.totalItems, 1)
    })
  })

  describe('Remote Announce Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let createNote = null
    let announce = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT)
      const follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await settle(MAIN_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await settle(REMOTE_PORT)
      createNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await settle(REMOTE_PORT)
      announce = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [actor2.id, PUBLIC],
        type: 'Announce',
        object: createNote.object.id
      })
      await settle(MAIN_PORT)
    })

    it('share is in the shares collection', async () => {
      assert(await isInStream(createNote.object.shares, announce, token2))
    })
  })

  describe('Remote Add Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let createNote = null
    let createAlbum = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT)
      const follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await settle(MAIN_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await settle(REMOTE_PORT)
      createAlbum = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Collection',
          nameMap: {
            en: 'Greatest greetings'
          },
          totalItems: 0,
          items: []
        }
      })
      await settle(REMOTE_PORT)
      createNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await settle(REMOTE_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor2.id, PUBLIC],
        type: 'Add',
        object: createNote.object.id,
        target: createAlbum.object.id
      })
      await settle(REMOTE_PORT)
    })

    it('correct count in proxy', async () => {
      const album = await getProxy(createAlbum.object.id, actor1, token1)
      assert.equal(album.totalItems, 1)
    })
  })

  describe('Remote Remove Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let createNote = null
    let createAlbum = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT)
      const follow = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await settle(MAIN_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await settle(REMOTE_PORT)
      createAlbum = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Collection',
          nameMap: {
            en: 'Greatest greetings'
          },
          totalItems: 0,
          items: []
        }
      })
      await settle(REMOTE_PORT)
      createNote = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await settle(REMOTE_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor2.id, PUBLIC],
        type: 'Add',
        object: createNote.object.id,
        target: createAlbum.object.id
      })
      await settle(REMOTE_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor2.id, PUBLIC],
        type: 'Remove',
        object: createNote.object.id,
        target: createAlbum.object.id
      })
      await settle(REMOTE_PORT)
    })

    it('correct count in proxy', async () => {
      const album = await getProxy(createAlbum.object.id, actor1, token1)
      assert.equal(album.totalItems, 0)
    })
  })

  describe('Undo Announce Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let createNote = null
    let announce = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor()
      createNote = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await settle(MAIN_PORT)
      announce = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Announce',
        object: createNote.object.id
      })
      await settle(REMOTE_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Undo',
        object: announce.id
      })
      await settle(REMOTE_PORT)
    })

    it('correct count of shares', async () => {
      const shares = await getObject(createNote.object.shares.id, token1)
      assert.equal(shares.totalItems, 0)
    })

    it('announce not in shares', async () => {
      assert(!(await isInStream(createNote.object.shares, announce, token1)))
    })
  })

  describe('Remote Undo Like Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let createNote = null
    let like = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT)
      const follow = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor1.id],
        type: 'Follow',
        object: actor1.id
      })
      await settle(REMOTE_PORT)
      await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [actor2.id],
        type: 'Accept',
        object: follow.id
      })
      await settle(MAIN_PORT)
      createNote = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await settle(MAIN_PORT)
      like = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC, actor1.id],
        type: 'Like',
        object: createNote.object.id
      })
      await settle(REMOTE_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC, actor1.id],
        type: 'Undo',
        object: like.id
      })
      await settle(REMOTE_PORT)
    })

    it('activity is not in object likes stream', async () => {
      assert(!(await isInStream(createNote.object.likes, like, token1)))
    })

    it('object likes count is correct', async () => {
      const likes = await getObject(createNote.object.likes.id, token1)
      assert.strictEqual(likes.totalItems, 0)
    })
  })

  describe('Remote Undo Announce Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let createNote = null
    let share = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT)
      const follow = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor1.id],
        type: 'Follow',
        object: actor1.id
      })
      await settle(REMOTE_PORT)
      await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [actor2.id],
        type: 'Accept',
        object: follow.id
      })
      await settle(MAIN_PORT)
      createNote = await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await settle(MAIN_PORT)
      share = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC, actor1.id],
        type: 'Announce',
        object: createNote.object.id
      })
      await settle(REMOTE_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC, actor1.id],
        type: 'Undo',
        object: share.id
      })
      await settle(REMOTE_PORT)
    })

    it('activity is not in object shares stream', async () => {
      assert(!(await isInStream(createNote.object.shares, share, token1)))
    })

    it('object shares count is correct', async () => {
      const shares = await getObject(createNote.object.shares.id, token1)
      assert.strictEqual(shares.totalItems, 0)
    })
  })

  describe('Remote Undo Follow Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let follow = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT)
      follow = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor1.id],
        type: 'Follow',
        object: actor1.id
      })
      await settle(REMOTE_PORT)
      await doActivity(actor1, token1, {
        '@context': AS2_CONTEXT,
        to: [actor2.id],
        type: 'Accept',
        object: follow.id
      })
      await settle(MAIN_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [PUBLIC, actor1.id],
        type: 'Undo',
        object: follow.id
      })
      await settle(REMOTE_PORT)
    })

    it('actor is no longer in followers', async () => {
      assert(!(await isInStream(actor1.followers, actor2, token1)))
    })

    it('other is no longer in following', async () => {
      assert(!(await isInStream(actor2.following, actor1, token2)))
    })

    it('actor is not in pending followers', async () => {
      assert(!(await isInStream(actor1.pendingFollowers, follow, token1)))
    })

    it('other is not in pending following', async () => {
      assert(!(await isInStream(actor2.pendingFollowing, follow, token2)))
    })
  })

  describe('Remote Undo Pending Follow Activity', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let follow = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT)
      follow = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor1.id],
        type: 'Follow',
        object: actor1.id
      })
      await settle(REMOTE_PORT)
      await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor1.id],
        type: 'Undo',
        object: follow.id
      })
      await settle(REMOTE_PORT)
    })

    it('actor is not in followers', async () => {
      assert(!(await isInStream(actor1.followers, actor2, token1)))
    })

    it('other is not in following', async () => {
      assert(!(await isInStream(actor2.following, actor1, token2)))
    })

    it('actor is no longer in pending followers', async () => {
      assert(!(await isInStream(actor1.pendingFollowers, follow, token1)))
    })

    it('other is no longer in pending following', async () => {
      assert(!(await isInStream(actor2.pendingFollowing, follow, token2)))
    })
  })

  describe('Update profile', () => {
    let actor1 = null
    let token1 = null
    let fetched = null
    before(async () => {
      [actor1, token1] = await registerActor()
      await doActivity(actor1, token1, {
        type: 'Update',
        object: {
          id: actor1.id,
          name: 'Ephemeral Test Actor',
          summaryMap: {
            en: 'Hello, I am a test actor!'
          }
        }
      })
      fetched = await getObject(actor1.id, token1)
    })

    it('actor has new name', async () => {
      assert.strictEqual(fetched.name, 'Ephemeral Test Actor')
    })

    it('actor has new summary', async () => {
      assert.strictEqual(fetched.summaryMap?.en, 'Hello, I am a test actor!')
    })
  })

  describe('Update profile with invalid data', () => {
    let actor1 = null
    let token1 = null
    const invalidUpdate = (prop) => {
      return {
        type: 'Update',
        object: {
          id: actor1.id,
          [prop]: 'INVALID'
        }
      }
    }
    before(async () => {
      [actor1, token1] = await registerActor()
    })

    it('fails on setting inbox', async () => {
      const status = await failActivity(actor1, token1, invalidUpdate('inbox'))
      assert(status >= 400 && status <= 499)
    })

    it('fails on setting followers', async () => {
      const status = await failActivity(
        actor1,
        token1,
        invalidUpdate('followers')
      )
      assert(status >= 400 && status <= 499)
    })

    it('fails on setting following', async () => {
      const status = await failActivity(
        actor1,
        token1,
        invalidUpdate('following')
      )
      assert(status >= 400 && status <= 499)
    })

    it('fails on setting liked', async () => {
      const status = await failActivity(actor1, token1, invalidUpdate('liked'))
      assert(status >= 400 && status <= 499)
    })

    it('fails on setting blocked', async () => {
      const status = await failActivity(
        actor1,
        token1,
        invalidUpdate('blocked')
      )
      assert(status >= 400 && status <= 499)
    })

    it('fails on setting pendingFollowers', async () => {
      const status = await failActivity(
        actor1,
        token1,
        invalidUpdate('pendingFollowers')
      )
      assert(status >= 400 && status <= 499)
    })

    it('fails on setting pendingFollowing', async () => {
      const status = await failActivity(
        actor1,
        token1,
        invalidUpdate('pendingFollowing')
      )
      assert(status >= 400 && status <= 499)
    })

    it('fails on setting outbox', async () => {
      const status = await failActivity(
        actor1,
        token1,
        invalidUpdate('outbox')
      )
      assert(status >= 400 && status <= 499)
    })
  })

  describe('Update profile with same data', () => {
    let actor1 = null
    let token1 = null
    const duplicateUpdate = (prop) => {
      return {
        type: 'Update',
        object: {
          id: actor1.id,
          [prop]: actor1[prop]
        }
      }
    }
    before(async () => {
      [actor1, token1] = await registerActor()
    })

    it('succeeds on setting duplicate inbox', async () => {
      let update = null
      try {
        update = await doActivity(actor1, token1, duplicateUpdate('inbox'))
      } catch (e) {
        assert(false)
      }
      assert.strictEqual(update.object?.inbox?.id, actor1.inbox)
    })

    it('succeeds on setting duplicate followers', async () => {
      const update = await doActivity(
        actor1,
        token1,
        duplicateUpdate('followers')
      )
      assert.strictEqual(update.object?.followers?.id, actor1.followers)
    })

    it('succeeds on setting duplicate following', async () => {
      const update = await doActivity(
        actor1,
        token1,
        duplicateUpdate('following')
      )
      assert.strictEqual(update.object?.following?.id, actor1.following)
    })

    it('succeeds on setting duplicate liked', async () => {
      const update = await doActivity(actor1, token1, duplicateUpdate('liked'))
      assert.strictEqual(update.object?.liked?.id, actor1.liked)
    })

    it('succeeds on setting duplicate blocked', async () => {
      const update = await doActivity(
        actor1,
        token1,
        duplicateUpdate('blocked')
      )
      assert.strictEqual(update.object?.blocked?.id, actor1.blocked?.id)
    })

    it('succeeds on setting duplicate pendingFollowers', async () => {
      const update = await doActivity(
        actor1,
        token1,
        duplicateUpdate('pendingFollowers')
      )
      assert.strictEqual(
        update.object?.pendingFollowers?.id,
        actor1.pendingFollowers?.id
      )
    })

    it('succeeds on setting duplicate pendingFollowing', async () => {
      const update = await doActivity(
        actor1,
        token1,
        duplicateUpdate('pendingFollowing')
      )
      assert.strictEqual(
        update.object?.pendingFollowing?.id,
        actor1.pendingFollowing?.id
      )
    })

    it('succeeds on setting duplicate outbox', async () => {
      const update = await doActivity(
        actor1,
        token1,
        duplicateUpdate('outbox')
      )
      assert.strictEqual(update.object?.outbox?.id, actor1.outbox)
    })
  })

  describe('Login', () => {
    let username = null
    let password = null

    before(async () => {
      [username, , password] = await registerUser()
    })

    it('can get Login page', async () => {
      const res = await fetch(`https://localhost:${MAIN_PORT}/login`)
      const body = await res.text()
      assert.strictEqual(res.status, 200)
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'text/html; charset=utf-8'
      )
      assert(body.includes('<form'))
      assert(body.includes('name="username"'))
      assert(body.includes('name="password"'))
      assert(body.includes('type="submit"'))
    })

    it('can log in a user', async () => {
      const res = await fetch(`https://localhost:${MAIN_PORT}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: querystring.stringify({
          username,
          password
        }),
        redirect: 'manual'
      })
      const body = await res.text()
      assert.strictEqual(
        res.status,
        302,
        `Bad status code ${res.status}: ${body}`
      )
      assert.ok(res.headers.get('Location'))
      assert.ok(res.headers.get('Set-Cookie'))
      const location = res.headers.get('Location')
      const cookie = res.headers.get('Set-Cookie')
      const res2 = await fetch(
        new URL(location, `https://localhost:${MAIN_PORT}/`),
        {
          headers: { Cookie: cookie }
        }
      )
      const body2 = await res2.text()
      assert.strictEqual(
        res2.status,
        200,
        `Bad status code ${res2.status}: ${body2}`
      )
      assert(body2.includes('Logged in'))
      assert(body2.includes(username))
      assert(body2.match('<span class="token">.+?</span>'))
    })
  })

  describe('Registration sets cookie', () => {
    it('can get cookie from registration', async () => {
      const username = 'testregcookie'
      const password = 'testregcookiepass'
      const reg = await fetch(`https://localhost:${MAIN_PORT}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: querystring.stringify({
          username,
          password,
          confirmation: password
        })
      })
      const text = await reg.text()
      assert.strictEqual(
        reg.status,
        200,
        `Bad status code ${reg.status}: ${text}`
      )
      const cookie = reg.headers.get('Set-Cookie')
      assert.ok(cookie)
      assert(cookie.match('sid'))
    })
  })

  describe('OAuth discovery by actor', () => {
    let actor = null

    before(async () => {
      [actor] = await registerActor()
    })

    it('has an OAuth authorization endpoint', async () => {
      assert.ok(actor.endpoints.oauthAuthorizationEndpoint)
    })

    it('has an OAuth token endpoint', async () => {
      assert.ok(actor.endpoints.oauthTokenEndpoint)
    })
  })

  describe('OAuth authorization endpoint', () => {
    let actor = null
    let cookie = null
    let code = null
    let csrfToken = null
    let accessToken = null
    let refreshToken = null
    let accessToken2 = null
    const scope = 'read write'
    const state = 'teststate'
    const codeVerifier = base64URLEncode(crypto.randomBytes(32))
    const hash = crypto.createHash('sha256').update(codeVerifier).digest()
    const codeChallenge = base64URLEncode(hash)

    before(async () => {
      [actor, , cookie] = await registerActor()
    })

    it('can get authorization form', async () => {
      const authz = actor.endpoints.oauthAuthorizationEndpoint
      const responseType = 'code'
      const qs = querystring.stringify({
        response_type: responseType,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope,
        state,
        code_challenge_method: 'S256',
        code_challenge: codeChallenge
      })
      const res = await fetch(`${authz}?${qs}`, {
        headers: { Cookie: cookie }
      })
      const body = await res.text()
      assert.strictEqual(res.status, 200)
      assert(body.includes('<form'))
      assert(body.includes('submit'))
      csrfToken = body.match(/name="csrf_token" value="(.+?)"/)[1]
    })

    it('can get authorization code', async () => {
      const authz = actor.endpoints.oauthAuthorizationEndpoint
      const res2 = await fetch(authz, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Cookie: cookie
        },
        body: querystring.stringify({
          csrf_token: csrfToken,
          client_id: CLIENT_ID,
          redirect_uri: REDIRECT_URI,
          scope,
          state,
          code_challenge: codeChallenge
        }),
        redirect: 'manual'
      })
      const body2 = await res2.text()
      assert.strictEqual(
        res2.status,
        302,
        `Bad status code ${res2.status}: ${body2}`
      )
      assert.ok(res2.headers.get('Location'))
      const location = res2.headers.get('Location')
      assert.strictEqual(
        location.substring(0, REDIRECT_URI.length),
        REDIRECT_URI
      )
      const locUrl = new URL(location)
      code = locUrl.searchParams.get('code')
      assert.ok(code)
      const state2 = locUrl.searchParams.get('state')
      assert.strictEqual(state2, state)
    })

    it('can get access code', async () => {
      const tokUrl = actor.endpoints.oauthTokenEndpoint
      const res3 = await fetch(tokUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: querystring.stringify({
          grant_type: 'authorization_code',
          code,
          redirect_uri: REDIRECT_URI,
          code_verifier: codeVerifier,
          client_id: CLIENT_ID
        })
      })
      const body3 = await res3.json()
      assert.strictEqual(
        res3.status,
        200,
        `Bad status code ${res3.status}: ${body3}`
      )
      assert.strictEqual(
        res3.headers.get('Content-Type'),
        'application/json; charset=utf-8'
      )
      accessToken = body3.access_token
      assert.ok(accessToken)
      assert.strictEqual(body3.token_type, 'Bearer')
      assert.ok(body3.scope)
      assert.ok(body3.expires_in)
      refreshToken = body3.refresh_token
      assert.ok(refreshToken)
    })

    it('can use the access token to read', async () => {
      const res = await fetch(actor.inbox, {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      })
      const body = await res.json()
      assert.strictEqual(
        res.status,
        200,
        `Bad status code ${res.status}: ${body}`
      )
    })

    it('can use the access token to write', async () => {
      const res = await fetch(actor.outbox, {
        method: 'POST',
        headers: {
          'Content-Type':
            'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
          Authorization: `Bearer ${accessToken}`
        },
        body: JSON.stringify({
          '@context': AS2_CONTEXT,
          type: 'IntransitiveActivity'
        })
      })
      const body = await res.json()
      assert.strictEqual(
        res.status,
        201,
        `Bad status code ${res.status}: ${body}`
      )
    })

    it('can get access code with refresh token', async () => {
      const tokUrl = actor.endpoints.oauthTokenEndpoint
      const res = await fetch(tokUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: querystring.stringify({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          scope
        })
      })
      const body = await res.json()
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'application/json; charset=utf-8'
      )
      accessToken2 = body.access_token
      assert.ok(accessToken2)
      assert.strictEqual(body.token_type, 'Bearer')
      assert.ok(body.scope)
      assert.ok(body.expires_in)
    })

    it('can use the refreshed access token to read', async () => {
      const res = await fetch(actor.inbox, {
        headers: {
          Authorization: `Bearer ${accessToken2}`
        }
      })
      const body = await res.json()
      assert.strictEqual(
        res.status,
        200,
        `Bad status code ${res.status}: ${body}`
      )
    })

    it('can use the refreshed access token to write', async () => {
      const res = await fetch(actor.outbox, {
        method: 'POST',
        headers: {
          'Content-Type':
            'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
          Authorization: `Bearer ${accessToken2}`
        },
        body: JSON.stringify({
          '@context': AS2_CONTEXT,
          type: 'IntransitiveActivity'
        })
      })
      const body = await res.json()
      assert.strictEqual(
        res.status,
        201,
        `Bad status code ${res.status}: ${body}`
      )
    })
  })

  describe('OAuth 2.0 read-only scope', () => {
    let actor = null
    let cookie = null
    let token = null
    let note = null
    before(async () => {
      [actor, , cookie] = await registerActor()
      const [actor2, token2] = await registerActor(REMOTE_PORT)
      const activity = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      note = activity.object
    })
    it('can get read-only access code', async () => {
      token = await getAccessToken(actor, cookie, 'read')
      assert.ok(token)
    })
    it('can use the read-only access token to read local', async () => {
      // This is a private collection so should only be available to the actor
      const pendingFollowers = await getObject(
        actor.pendingFollowers.id,
        token
      )
      assert.strictEqual(pendingFollowers.totalItems, 0)
    })
    it('can use the read-only access token to read remote', async () => {
      const remoteNote = await getProxy(note.id, actor, token)
      assert.ok(remoteNote)
      assert.strictEqual(remoteNote.contentMap?.en, 'Hello, world!')
    })
    it('cannot use the read-only access token to write', async () => {
      const status = await failActivity(actor, token, {
        '@context': AS2_CONTEXT,
        type: 'IntransitiveActivity'
      })
      assert.strictEqual(status, 403)
    })
  })

  describe('OAuth 2.0 write-only scope', () => {
    let actor = null
    let cookie = null
    let token = null
    let note = null
    before(async () => {
      [actor, , cookie] = await registerActor()
      const [actor2, token2] = await registerActor(REMOTE_PORT)
      const activity = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      note = activity.object
    })
    it('can get write-only access code', async () => {
      token = await getAccessToken(actor, cookie, 'write')
      assert.ok(token)
    })
    it('can use the write-only access token to write', async () => {
      const activity = await doActivity(actor, token, {
        '@context': AS2_CONTEXT,
        type: 'IntransitiveActivity'
      })
      assert.ok(activity)
    })
    it('cannot use the write-only access token to read local', async () => {
      // This is a private collection so should only be available to the actor
      const res = await fetch(actor.pendingFollowers.id, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      })
      assert.strictEqual(res.status, 403)
    })
    it('cannot use the write-only access token to read remote', async () => {
      assert(!(await canGetProxy(note.id, actor, token)))
    })
  })

  describe('Cannot use authorization code as access token', () => {
    let actor = null
    let code = null
    let note = null
    before(async () => {
      let cookie = null;
      [actor, , cookie] = await registerActor()
      code = await getAuthCode(actor, cookie)
      const [actor2, token2] = await registerActor(REMOTE_PORT)
      const activity = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      note = activity.object
    })
    it('cannot use the authorization code to read', async () => {
      // This is a private collection so should only be available to the actor
      const res = await fetch(actor.pendingFollowers.id, {
        headers: {
          Authorization: `Bearer ${code}`
        }
      })
      assert.strictEqual(res.status, 401)
      const body = await res.json()
      assert.strictEqual(body.error, 'invalid_token')
      assert(body.error_description)
    })
    it('cannot use the authorization code to write', async () => {
      const status = await failActivity(actor, code, {
        '@context': AS2_CONTEXT,
        type: 'IntransitiveActivity'
      })
      assert.strictEqual(status, 401)
    })
    it('cannot use the authorization code to read through proxy', async () => {
      const res = await fetch(actor.endpoints.proxyUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Bearer ${code}`
        },
        body: querystring.stringify({ id: note.id })
      })
      assert.strictEqual(res.status, 401)
      const body = await res.json()
      assert.strictEqual(body.error, 'invalid_token')
      assert(body.error_description)
    })
  })

  describe('Cannot use refresh token as access token', () => {
    let actor = null
    let refreshToken = null
    let note = null
    before(async () => {
      let cookie = null;
      [actor, , cookie] = await registerActor()
      const [code, codeVerifier] = await getAuthCode(actor, cookie);
      [, refreshToken] = await getTokens(actor, code, codeVerifier)
      const [actor2, token2] = await registerActor(REMOTE_PORT)
      const activity = await doActivity(actor2, token2, {
        '@context': AS2_CONTEXT,
        to: [actor.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      note = activity.object
    })
    it('cannot use the refresh token to read', async () => {
      // This is a private collection so should only be available to the actor
      const res = await fetch(actor.pendingFollowers.id, {
        headers: {
          Authorization: `Bearer ${refreshToken}`
        }
      })
      assert.strictEqual(res.status, 401)
      const body = await res.json()
      assert.strictEqual(body.error, 'invalid_token')
      assert(body.error_description)
    })
    it('cannot use the authorization code to write', async () => {
      const status = await failActivity(actor, refreshToken, {
        '@context': AS2_CONTEXT,
        type: 'IntransitiveActivity'
      })
      assert.strictEqual(status, 401)
    })
    it('cannot use the authorization code to read through proxy', async () => {
      const res = await fetch(actor.endpoints.proxyUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Bearer ${refreshToken}`
        },
        body: querystring.stringify({ id: note.id })
      })
      assert.strictEqual(res.status, 401)
      const body = await res.json()
      assert.strictEqual(body.error, 'invalid_token')
      assert(body.error_description)
    })
  })

  describe('Add Bootstrap', () => {
    let username = null
    let actor = null
    let password = null
    let cookie = null
    before(async () => {
      [username, , password, cookie] = await registerUser()
      actor = await userToActor(username)
    })
    it('bootstrap in registration form', async () => {
      const res = await fetch(`https://localhost:${MAIN_PORT}/register`)
      const body = await res.text()
      assert.match(
        body,
        /<link rel="stylesheet" href="\/bootstrap\/css\/bootstrap.min.css">/
      )
      assert.match(
        body,
        /<script src="\/bootstrap\/js\/bootstrap.min.js"><\/script>/
      )
      assert.match(body, /<script src="\/popper\/popper.min.js"><\/script>/)
    })
    it('bootstrap in login form', async () => {
      const res = await fetch(`https://localhost:${MAIN_PORT}/login`)
      const body = await res.text()
      assert.match(
        body,
        /<link rel="stylesheet" href="\/bootstrap\/css\/bootstrap.min.css">/
      )
      assert.match(
        body,
        /<script src="\/bootstrap\/js\/bootstrap.min.js"><\/script>/
      )
      assert.match(body, /<script src="\/popper\/popper.min.js"><\/script>/)
    })
    it('bootstrap in registration results', async () => {
      const username = 'testbootstrap'
      const password = 'testbootstrap'
      const res = await fetch(`https://localhost:${MAIN_PORT}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: querystring.stringify({
          username,
          password,
          confirmation: password
        })
      })
      const body = await res.text()
      assert.match(
        body,
        /<link rel="stylesheet" href="\/bootstrap\/css\/bootstrap.min.css">/
      )
      assert.match(
        body,
        /<script src="\/bootstrap\/js\/bootstrap.min.js"><\/script>/
      )
      assert.match(body, /<script src="\/popper\/popper.min.js"><\/script>/)
    })
    it('bootstrap in login results', async () => {
      // NB: registered in previous test
      const res = await fetch(`https://localhost:${MAIN_PORT}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: querystring.stringify({
          username,
          password
        }),
        redirect: 'manual'
      })
      const location = res.headers.get('Location')
      const cookie = res.headers.get('Set-Cookie')
      const res2 = await fetch(
        new URL(location, `https://localhost:${MAIN_PORT}/`),
        {
          headers: { Cookie: cookie }
        }
      )
      const body2 = await res2.text()
      assert.match(
        body2,
        /<link rel="stylesheet" href="\/bootstrap\/css\/bootstrap.min.css">/
      )
      assert.match(
        body2,
        /<script src="\/bootstrap\/js\/bootstrap.min.js"><\/script>/
      )
      assert.match(body2, /<script src="\/popper\/popper.min.js"><\/script>/)
    })
    it('bootstrap in authorization form', async () => {
      const state = crypto.randomBytes(16).toString('hex')
      const authz = actor.endpoints.oauthAuthorizationEndpoint
      const responseType = 'code'
      const scope = 'read write'
      const codeVerifier = crypto.randomBytes(32).toString('hex')
      const codeChallenge = base64URLEncode(
        crypto.createHash('sha256').update(codeVerifier).digest()
      )
      const qs = querystring.stringify({
        response_type: responseType,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope,
        state,
        code_challenge_method: 'S256',
        code_challenge: codeChallenge
      })
      const res = await fetch(`${authz}?${qs}`, {
        headers: { Cookie: cookie }
      })
      const body = await res.text()
      assert.match(
        body,
        /<link rel="stylesheet" href="\/bootstrap\/css\/bootstrap.min.css">/
      )
      assert.match(
        body,
        /<script src="\/bootstrap\/js\/bootstrap.min.js"><\/script>/
      )
      assert.match(body, /<script src="\/popper\/popper.min.js"><\/script>/)
    })
  })

  describe('Cannot overwrite object properties', () => {
    let actor = null
    let token = null
    let object = null
    before(async () => {
      [actor, token] = await registerActor()
      const activity = await doActivity(actor, token, {
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, World!'
          }
        }
      })
      object = activity.object
    })

    it('cannot change id', async () => {
      assert(
        await cantUpdate(actor, token, object, {
          id: 'https://example.com/object/1'
        })
      )
    })

    it('cannot change replies', async () => {
      assert(
        await cantUpdate(actor, token, object, {
          replies: 'https://example.com/collection/3'
        })
      )
    })

    it('cannot change likes', async () => {
      assert(
        await cantUpdate(actor, token, object, {
          likes: 'https://example.com/collection/4'
        })
      )
    })

    it('cannot change shares', async () => {
      assert(
        await cantUpdate(actor, token, object, {
          shares: 'https://example.com/collection/5'
        })
      )
    })

    it('cannot change published', async () => {
      assert(
        await cantUpdate(actor, token, object, {
          published: '20230920T00:00:00Z'
        })
      )
    })

    it('cannot change updated', async () => {
      assert(
        await cantUpdate(actor, token, object, {
          updated: '20230920T00:00:00Z'
        })
      )
    })

    it('cannot change attributedTo', async () => {
      assert(
        await cantUpdate(actor, token, object, {
          attributedTo: 'https://example.com/user/3'
        })
      )
    })
  })

  describe('Cannot overwrite collection properties', () => {
    let actor = null
    let token = null
    let object = null
    before(async () => {
      [actor, token] = await registerActor()
      object = actor.followers
    })

    it('cannot change first', async () => {
      assert(
        await cantUpdate(actor, token, object, {
          first: 'https://example.com/object/1'
        })
      )
    })

    it('cannot change last', async () => {
      assert(
        await cantUpdate(actor, token, object, {
          last: 'https://example.com/collection/3'
        })
      )
    })

    it('cannot change current', async () => {
      assert(
        await cantUpdate(actor, token, object, {
          current: 'https://example.com/collection/4'
        })
      )
    })

    it('cannot change items', async () => {
      assert(
        await cantUpdate(actor, token, object, {
          items: ['https://example.com/foo/bar']
        })
      )
    })

    it('cannot change orderedItems', async () => {
      assert(
        await cantUpdate(actor, token, object, {
          orderedItems: ['https://example.com/foo/bar']
        })
      )
    })

    it('cannot change totalItems', async () => {
      assert(await cantUpdate(actor, token, object, { totalItems: 69 }))
    })
  })

  describe('Cannot overwrite collection page properties', () => {
    let actor = null
    let token = null
    before(async () => {
      [actor, token] = await registerActor()
    })

    it('cannot change next', async () => {
      const coll = await getObject(actor.followers, token)
      const object = await getObject(coll.first.id, token)
      assert(
        await cantUpdate(actor, token, object, {
          next: 'https://example.com/object/1'
        })
      )
    })

    it('cannot change prev', async () => {
      const coll = await getObject(actor.followers, token)
      const object = await getObject(coll.first.id, token)
      assert(
        await cantUpdate(actor, token, object, {
          prev: 'https://example.com/collection/3'
        })
      )
    })

    it('cannot change partOf', async () => {
      const coll = await getObject(actor.followers, token)
      const object = await getObject(coll.first.id, token)
      assert(
        await cantUpdate(actor, token, object, {
          partOf: 'https://example.com/collection/25'
        })
      )
    })

    it('cannot change items', async () => {
      const coll = await getObject(actor.followers, token)
      const object = await getObject(coll.first.id, token)
      assert(
        await cantUpdate(actor, token, object, {
          items: ['https://example.com/foo/bar']
        })
      )
    })

    it('cannot change orderedItems', async () => {
      const coll = await getObject(actor.followers, token)
      const object = await getObject(coll.first.id, token)
      assert(
        await cantUpdate(actor, token, object, {
          orderedItems: ['https://example.com/foo/bar']
        })
      )
    })

    it('cannot change startIndex', async () => {
      const coll = await getObject(actor.followers, token)
      const object = await getObject(coll.first.id, token)
      assert(await cantUpdate(actor, token, object, { startIndex: 50 }))
    })
  })

  describe('Multiple activity types', () => {
    let actor = null
    let token = null
    let activity = null
    before(async () => {
      [actor, token] = await registerActor()
    })
    it('can post an activity with multiple types', async () => {
      activity = await doActivity(actor, token, {
        '@context': [
          AS2_CONTEXT,
          {
            Meditate: {
              '@type': '@id'
            }
          }
        ],
        type: ['Meditate', 'IntransitiveActivity']
      })
      assert.ok(activity)
    })
    it('activity has multiple types', async () => {
      assert(Array.isArray(activity.type))
      assert(activity.type.includes('Meditate'))
      assert(activity.type.includes('IntransitiveActivity'))
    })
    it('can fetch new activity', async () => {
      const act2 = await getObject(activity.id, token)
      assert(Array.isArray(act2.type))
      assert(act2.type.includes('Meditate'))
      assert(act2.type.includes('IntransitiveActivity'))
    })
  })

  describe('Implicit create', () => {
    let actor = null
    let token = null
    before(async () => {
      [actor, token] = await registerActor()
    })
    it('known type is wrapped a Create activity', async () => {
      const activity = await doActivity(actor, token, {
        type: 'Note',
        contentMap: {
          en: 'Hello, World!'
        }
      })
      assert.ok(activity.id)
      assert.strictEqual(activity.type, 'Create')
      assert.ok(activity.object)
      assert.strictEqual(activity.object.type, 'Note')
      assert.ok(activity.object.contentMap)
      assert.strictEqual(activity.object.contentMap.en, 'Hello, World!')
    })

    it('extension type with known object type is wrapped', async () => {
      const activity = await doActivity(actor, token, {
        '@context': [
          AS2_CONTEXT,
          {
            test: 'https://evanp.github.io/onepage.pub/test#',
            Salute: {
              '@id': 'test:Salute',
              '@type': '@id'
            }
          }
        ],
        type: ['Salute', 'Note'],
        contentMap: {
          en: 'Hello, World!'
        }
      })
      assert.ok(activity.id)
      assert.strictEqual(activity.type, 'Create')
      assert.ok(activity.object)
      assert.ok(activity.object.type.includes('Note'))
      assert.ok(activity.object.type.includes('Salute'))
      assert.ok(activity.object.contentMap)
      assert.strictEqual(activity.object.contentMap.en, 'Hello, World!')
    })

    it('extension type with known activity type is not wrapped', async () => {
      const activity = await doActivity(actor, token, {
        '@context': [
          AS2_CONTEXT,
          {
            test: 'https://evanp.github.io/onepage.pub/test#',
            Think: {
              '@id': 'test:Think',
              '@type': '@id'
            }
          }
        ],
        type: ['Think', 'IntransitiveActivity']
      })
      assert.ok(activity.id)
      assert.ok(activity.type.includes('Think'))
      assert.ok(activity.type.includes('IntransitiveActivity'))
    })

    it('extension type with ducktype properties is not wrapped', async () => {
      const activity = await doActivity(actor, token, {
        '@context': [
          AS2_CONTEXT,
          {
            test: 'https://evanp.github.io/onepage.pub/test#',
            Bake: {
              '@id': 'test:Bake',
              '@type': '@id'
            },
            Cake: {
              '@id': 'test:Cake',
              '@type': '@id'
            }
          }
        ],
        type: 'Bake',
        object: {
          type: 'Cake',
          nameMap: {
            en: 'A chocolate cake'
          }
        }
      })
      assert.ok(activity.id)
      assert.ok(activity.type.includes('Bake'))
      assert.ok(activity.type.includes('Activity'))
    })

    it('extension type without ducktype properties is not wrapped', async () => {
      const activity = await doActivity(actor, token, {
        '@context': [
          AS2_CONTEXT,
          {
            test: 'https://evanp.github.io/onepage.pub/test#',
            Cake: {
              '@id': 'test:Cake',
              '@type': '@id'
            }
          }
        ],
        type: 'Cake',
        nameMap: {
          en: 'A chocolate cake'
        }
      })
      assert.ok(activity.id)
      assert.strictEqual(activity.type, 'Create')
      assert.ok(activity.object.type.includes('Cake'))
      assert.ok(activity.object.type.includes('Object'))
    })

    it('absent type without ducktype properties is not wrapped', async () => {
      const activity = await doActivity(actor, token, {
        nameMap: {
          en: 'A chocolate cake'
        }
      })
      assert.ok(activity.id)
      assert.strictEqual(activity.type, 'Create')
      assert.strictEqual(activity.object.type, 'Object')
    })

    it('absent type with ducktype properties is not wrapped', async () => {
      const activity = await doActivity(actor, token, {
        instrument: {
          id: 'http://foo.example/object/app',
          type: 'Application',
          nameMap: {
            en: 'MyCoolApp'
          }
        }
      })
      assert.ok(activity.id)
      assert.strictEqual(activity.type, 'Activity')
    })
  })

  describe('Invitation code', () => {
    const CODE = 'icky-serving-18750'
    let server = null
    before(async () => {
      server = await startServer(THIRD_PORT, { OPP_INVITE_CODE: CODE })
    })
    after(() => {
      server.kill()
    })
    it('registration form has invitation code input', async () => {
      const res = await fetch(`https://localhost:${THIRD_PORT}/register`)
      const body = await res.text()
      assert(body.includes('name="invitecode"'))
    })
    it('registration without an invitation code fails', async () => {
      const username = 'testusernocode1'
      const password = 'testpasswordnocode1'
      const res = await fetch(`https://localhost:${THIRD_PORT}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: querystring.stringify({
          username,
          password,
          confirmation: password
        })
      })
      const body = await res.text()
      assert.strictEqual(
        res.status,
        400,
        `Bad status code ${res.status}: ${body}`
      )
    })
    it('registration with wrong invitation code fails', async () => {
      const username = 'testuserbadcode1'
      const password = 'testpasswordbadcode1'
      const res = await fetch(`https://localhost:${THIRD_PORT}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: querystring.stringify({
          username,
          password,
          confirmation: password,
          invitecode: 'bad-code-11111'
        })
      })
      const body = await res.text()
      assert.strictEqual(
        res.status,
        400,
        `Bad status code ${res.status}: ${body}`
      )
    })
    it('registration with correct invitation code succeeds', async () => {
      const username = 'testusergoodcode1'
      const password = 'testpasswordgoodcode1'
      const res = await fetch(`https://localhost:${MAIN_PORT}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: querystring.stringify({
          username,
          password,
          confirmation: password,
          invitecode: CODE
        })
      })
      const body = await res.text()
      assert.strictEqual(
        res.status,
        200,
        `Bad status code ${res.status}: ${body}`
      )
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'text/html; charset=utf-8'
      )
      assert(body.includes('Registered'))
      assert(body.includes(username))
      assert(body.match('<span class="token">.+?</span>'))
    })
  })

  describe('Blocklist file', () => {
    let [actor1, token1] = [null, null]
    let [actor2, token2] = [null, null]
    let [actor3, token3] = [null, null]
    let server = null
    let created = null
    before(async () => {
      // TODO: figure out how to set the path for the blocklist better
      server = await startServer(FOURTH_PORT, {
        OPP_BLOCK_LIST: path.join('.', 'blocklist.csv')
      });
      [actor1, token1] = await registerActor(MAIN_PORT);
      [actor2, token2] = await registerActor(REMOTE_PORT);
      [actor3, token3] = await registerActor(FOURTH_PORT)
      created = await doActivity(actor3, token3, {
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, World!'
          }
        }
      })
      await settle(FOURTH_PORT)
    })
    after(async () => {
      await settle(MAIN_PORT)
      await settle(REMOTE_PORT)
      await settle(FOURTH_PORT)
      server.kill()
    })

    it('can receive from unblocked', async () => {
      const activity = await doActivity(actor1, token1, {
        to: [actor3.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: `Hello, ${actor3.name}!`
          }
        }
      })
      await settle(MAIN_PORT)
      assert.ok(isInStream(actor3.inbox, activity, token3))
    })

    it('cannot receive from blocked', async () => {
      const activity = await doActivity(actor2, token2, {
        to: [actor3.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: `Hello, ${actor3.name}!`
          }
        }
      })
      await settle(REMOTE_PORT)
      assert.ok(!(await isInStream(actor3.inbox, activity, token3)))
    })

    it('will accept read from unblocked', async () => {
      assert.ok(await canGetProxy(created.object.id, actor1, token1))
    })

    it('will not accept read from blocked', async () => {
      assert.ok(!(await canGetProxy(created.object.id, actor2, token2)))
    })
  })

  describe('Validate OAuth client ID', () => {
    let actor = null
    let authz = null
    let cookie = null
    const responseType = 'code'
    const scope = 'read write'
    const state = 'teststate'
    const codeVerifier = base64URLEncode(crypto.randomBytes(32))
    const hash = crypto.createHash('sha256').update(codeVerifier).digest()
    const codeChallenge = base64URLEncode(hash)
    let nonAS2Server = null
    let mismatchUriServer = null

    before(async () => {
      [actor, , cookie] = await registerActor()
      authz = actor.endpoints.oauthAuthorizationEndpoint
      const nonAS2Client =
        'name: foo\n' +
        'type: bar\n' +
        'redirectURI: https://notimportant.example/callback'
      nonAS2Server = await startClientServer(
        THIRD_PORT,
        nonAS2Client,
        'application/yaml'
      )
      const mismatchUriClient = {
        ...defaultClient,
        redirectURI: 'https://mismatch.example/callback'
      }
      mismatchUriServer = await startClientServer(
        FOURTH_PORT,
        JSON.stringify(mismatchUriClient)
      )
    })
    after(async () => {
      nonAS2Server.close()
      mismatchUriServer.close()
    })
    it('refuses client ID that is not an HTTPS URL', async () => {
      const responseType = 'code'
      const qs = querystring.stringify({
        response_type: responseType,
        client_id: 'urn:uuid:C792DF04-9B6D-4545-BC9D-9F35FECA2B58',
        redirect_uri: REDIRECT_URI,
        scope,
        state,
        code_challenge_method: 'S256',
        code_challenge: codeChallenge
      })
      const res = await fetch(`${authz}?${qs}`, {
        headers: { Cookie: cookie }
      })
      assert.ok(
        res.status >= 400 && res.status < 500,
        `Bad status code ${res.status}`
      )
    })
    it('refuses client ID that does not exist', async () => {
      const qs = querystring.stringify({
        response_type: responseType,
        client_id: 'https://dne.example/client',
        redirect_uri: REDIRECT_URI,
        scope,
        state,
        code_challenge_method: 'S256',
        code_challenge: codeChallenge
      })
      const res = await fetch(`${authz}?${qs}`, {
        headers: { Cookie: cookie }
      })
      assert.ok(
        res.status >= 400 && res.status < 500,
        `Bad status code ${res.status}`
      )
    })
    it('refuses client ID that does not return an AS2 object', async () => {
      const qs = querystring.stringify({
        response_type: responseType,
        client_id: `https://localhost:${THIRD_PORT}/client`,
        redirect_uri: REDIRECT_URI,
        scope,
        state,
        code_challenge_method: 'S256',
        code_challenge: codeChallenge
      })
      const res = await fetch(`${authz}?${qs}`, {
        headers: { Cookie: cookie }
      })
      assert.ok(
        res.status >= 400 && res.status < 500,
        `Bad status code ${res.status}`
      )
    })
    it('refuses client ID that does not have a matching redirectURI', async () => {
      const qs = querystring.stringify({
        response_type: responseType,
        client_id: `https://localhost:${FOURTH_PORT}/client`,
        redirect_uri: REDIRECT_URI,
        scope,
        state,
        code_challenge_method: 'S256',
        code_challenge: codeChallenge
      })
      const res = await fetch(`${authz}?${qs}`, {
        headers: { Cookie: cookie }
      })
      assert.ok(
        res.status >= 400 && res.status < 500,
        `Bad status code ${res.status}`
      )
    })
  })

  describe('Proxy mode', () => {
    let process = null
    before(async () => {
      process = await startServer(THIRD_PORT, {
        OPP_ORIGIN: 'https://social.example'
      })
    })
    after(async () => {
      process.kill('SIGTERM')
    })
    it('responds to HTTP requests', async () => {
      const res = await fetch(`http://localhost:${THIRD_PORT}/`)
      assert.strictEqual(res.status, 200)
    })
    it('uses origin URLs for server ID', async () => {
      const res = await fetch(`http://localhost:${THIRD_PORT}/`, {
        headers: { Accept: 'application/activity+json' }
      })
      const json = await res.json()
      assert.strictEqual(json.id, 'https://social.example/')
    })
    it('can register a user', async () => {
      const username = 'proxyuser1'
      const password = 'proxypassword1'
      const reg = await fetch(`http://localhost:${THIRD_PORT}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: querystring.stringify({
          username,
          password,
          confirmation: password
        })
      })
      const text = await reg.text()
      assert.ok(text.match(/<span class="token">(.*?)<\/span>/))
      assert.ok(reg.headers.get('Set-Cookie'))
    })
    it('readiness endpoint works', async () => {
      const res = await fetch(`http://localhost:${THIRD_PORT}/ready`)
      assert.strictEqual(res.status, 200)
    })
    it('liveness endpoint works', async () => {
      const res = await fetch(`http://localhost:${THIRD_PORT}/live`)
      assert.strictEqual(res.status, 200)
    })
  })

  describe('Version in footer', () => {
    it('version in main page footer', async () => {
      const res = await fetch(`https://localhost:${MAIN_PORT}/`)
      const body = await res.text()
      assert.match(body, /<span class="version">.+?<\/span>/)
    })

    it('version in registration page footer', async () => {
      const res = await fetch(`https://localhost:${MAIN_PORT}/register`)
      const body = await res.text()
      assert.match(body, /<span class="version">.+?<\/span>/)
    })

    it('version in login page footer', async () => {
      const res = await fetch(`https://localhost:${MAIN_PORT}/login`)
      const body = await res.text()
      assert.match(body, /<span class="version">.+?<\/span>/)
    })
  })

  describe('Authorization when unauthenticated', () => {
    let actor = null
    const responseType = 'code'
    const scope = 'read write'
    const state = 'teststate'
    const codeVerifier = base64URLEncode(crypto.randomBytes(32))
    const hash = crypto.createHash('sha256').update(codeVerifier).digest()
    const codeChallenge = base64URLEncode(hash)
    let authz = null
    let username = null
    let password = null

    before(async () => {
      [username, , password] = await registerUser()
      actor = await userToActor(username)
      authz = actor.endpoints.oauthAuthorizationEndpoint
    })

    it('redirects to login if unauthenticated', async () => {
      const qs = querystring.stringify({
        response_type: responseType,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope,
        state,
        code_challenge_method: 'S256',
        code_challenge: codeChallenge
      })
      const res = await fetch(`${authz}?${qs}`, { redirect: 'manual' })
      assert.strictEqual(res.status, 302)
      const location = res.headers.get('Location')
      assert.strictEqual(location, '/login')
      const cookie = res.headers.get('Set-Cookie')
      assert.ok(cookie)

      const res2 = await fetch(
        new URL(location, `https://localhost:${MAIN_PORT}/`),
        { headers: { Cookie: cookie } }
      )
      assert.strictEqual(res2.status, 200)

      const res3 = await fetch(`https://localhost:${MAIN_PORT}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Cookie: cookie
        },
        body: querystring.stringify({
          username,
          password
        }),
        redirect: 'manual'
      })
      const body3 = await res3.text()
      assert.strictEqual(
        res3.status,
        302,
        `Bad status code ${res3.status}: ${body3}`
      )
      const location2 = res3.headers.get('Location')
      assert.ok(location2.startsWith('/endpoint/oauth/authorize'))
      const cookie2 = res3.headers.get('Set-Cookie')
      const res5 = await fetch(
        new URL(location2, `https://localhost:${MAIN_PORT}/`),
        {
          headers: { Cookie: cookie2 },
          redirect: 'manual'
        }
      )
      const body5 = await res5.text()
      assert.strictEqual(
        res5.status,
        200,
        `Bad status code ${res5.status}: ${body5}`
      )
      assert(body5.includes('Authorize'))
      assert(body5.includes(CLIENT_ID))
    })
  })

  describe('HTTP Signature with fragment in ID', async () => {
    let actor = null
    let peer = null
    let pair = null
    const keyId = `https://localhost:${FIFTH_PORT}/actor#main-key`
    let clientActor = null
    let clientNote = null
    let clientActivity = null

    before(async () => {
      [actor] = await registerActor()
      pair = await generateKeyPair('rsa', {
        modulusLength: 2048,
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'pem'
        },
        publicKeyEncoding: {
          type: 'pkcs1',
          format: 'pem'
        }
      })
      clientActor = {
        id: `https://localhost:${FIFTH_PORT}/actor`,
        type: 'Person',
        preferredUsername: 'peer',
        publicKey: {
          id: `https://localhost:${FIFTH_PORT}/actor#main-key`,
          owner: `https://localhost:${FIFTH_PORT}/actor`,
          publicKeyPem: pair.publicKey
        },
        published: '2023-09-20T00:00:00Z'
      }
      clientNote = {
        id: `https://localhost:${FIFTH_PORT}/note`,
        type: 'Note',
        contentMap: {
          en: 'Hello, World!'
        },
        published: '2023-09-20T00:00:00Z'
      }
      clientActivity = {
        id: `https://localhost:${FIFTH_PORT}/activity`,
        actor: {
          id: clientActor.id,
          type: clientActor.type,
          preferredUsername: clientActor.preferredUsername
        },
        type: 'Create',
        to: [actor.id],
        object: clientNote
      }
      peer = https.createServer(
        {
          key: fs.readFileSync('localhost.key'),
          cert: fs.readFileSync('localhost.crt')
        },
        (req, res) => {
          if (req.url === '/actor') {
            res.writeHead(200)
            res.end(
              JSON.stringify({
                '@context': AS2_CONTEXT,
                ...clientActor
              })
            )
          } else if (req.url === '/note') {
            res.writeHead(200)
            res.end(
              JSON.stringify({
                '@context': AS2_CONTEXT,
                ...clientNote
              })
            )
          } else if (req.url === '/activity') {
            res.writeHead(200)
            res.end(
              JSON.stringify({
                '@context': AS2_CONTEXT,
                ...clientActivity
              })
            )
          } else {
            res.writeHead(404)
            res.end('Not found')
          }
        }
      )
      peer.listen(FIFTH_PORT)
    })

    after(async () => {
      peer.close()
    })

    it('Can send a signed request', async () => {
      const inbox = actor.inbox
      const date = new Date().toUTCString()
      const body = JSON.stringify({
        '@context': AS2_CONTEXT,
        ...clientActivity
      })
      const hash = crypto.createHash('sha256')
      hash.update(body)
      const digest = `sha-256=${hash.digest('base64')}`

      const header = await signRequest(
        keyId,
        pair.privateKey,
        'POST',
        inbox,
        date,
        digest
      )
      const res = await fetch(inbox, {
        method: 'POST',
        headers: {
          'Content-Type': AS2_MEDIA_TYPE,
          Signature: header,
          Date: date,
          Digest: digest
        },
        body
      })
      const resBody = await res.text()
      assert.ok(
        res.status >= 200 && res.status < 300,
        `Bad status ${res.status} for delivery to ${inbox}: ${resBody}`
      )
    })
  })

  describe('Upload files', () => {
    let actor = null
    let token = null
    let implicitCreate = null
    let explicitCreate = null
    let token2 = null

    before(async () => {
      [actor, token] = await registerActor();
      [, token2] = await registerActor()
    })

    it('has an uploadMedia endpoint', async () => {
      assert.ok(actor.endpoints.uploadMedia)
    })

    it('can upload a file with implicit Create', async () => {
      const formData = new FormData()

      const jsonPayload = JSON.stringify({
        to: [actor.followers],
        type: 'Image',
        name: 'test.png',
        summaryMap: { en: 'An image with the word "test"' }
      })
      const jsonBlob = new Blob([jsonPayload], {
        type: 'application/activity+json'
      })
      formData.append('object', jsonBlob)

      // Add image/png file
      const imageFile = fs.readFileSync('test.png')
      const imageBlob = new Blob([imageFile], { type: 'image/png' })
      formData.append('file', imageBlob, 'test.png')

      // POST request with fetch
      const res = await fetch(actor.endpoints.uploadMedia, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`
        },
        body: formData
      })
      const resBody = await res.text()
      assert.ok(
        res.status >= 200 && res.status < 300,
        `Bad status ${res.status}: ${resBody}`
      )
      implicitCreate = res.headers.get('Location')
      assert.ok(implicitCreate)
    })

    it('can upload a file with explicit Create', async () => {
      const formData = new FormData()

      const jsonPayload = JSON.stringify({
        type: 'Create',
        to: [actor.followers],
        object: {
          type: 'Image',
          name: 'test.png',
          summaryMap: { en: 'An image with the word "test"' }
        }
      })
      const jsonBlob = new Blob([jsonPayload], {
        type: 'application/activity+json'
      })
      formData.append('object', jsonBlob)

      // Add image/png file
      const imageFile = fs.readFileSync('test.png')
      const imageBlob = new Blob([imageFile], { type: 'image/png' })
      formData.append('file', imageBlob, 'test.png')

      // POST request with fetch
      const res = await fetch(actor.endpoints.uploadMedia, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`
        },
        body: formData
      })
      const resBody = await res.text()
      assert.ok(
        res.status >= 200 && res.status < 300,
        `Bad status ${res.status}: ${resBody}`
      )
      explicitCreate = res.headers.get('Location')
      assert.ok(explicitCreate)
    })

    it('can find the implicit Create in the outbox', async () => {
      assert.ok(implicitCreate)
      assert.ok(isInStream(actor.outbox, implicitCreate, token))
    })

    it('can find the explicit Create in the outbox', async () => {
      assert.ok(explicitCreate)
      assert.ok(isInStream(actor.outbox, explicitCreate, token))
    })

    it('can get the implicitly created file', async () => {
      assert.ok(implicitCreate)
      const act = await getObject(implicitCreate, token)
      const res = await fetch(act.object.url, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      })
      const buffer = await res.arrayBuffer()
      assert.ok(
        res.status >= 200 && res.status < 300,
        `Bad status ${res.status}`
      )
      assert.ok(buffer.byteLength > 0)
    })

    it('can get the explicitly created file', async () => {
      assert.ok(explicitCreate)
      const act = await getObject(explicitCreate, token)
      const res = await fetch(act.object.url, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      })
      const buffer = await res.arrayBuffer()
      assert.ok(
        res.status >= 200 && res.status < 300,
        `Bad status ${res.status}`
      )
      assert.ok(buffer.byteLength > 0)
    })

    it("can't get the file without a token", async () => {
      assert.ok(implicitCreate)
      const act = await getObject(implicitCreate, token)
      const res = await fetch(act.object.url)
      assert.strictEqual(res.status, 401)
    })

    it("can't get the file with an unauthorized token", async () => {
      assert.ok(implicitCreate)
      const act = await getObject(implicitCreate, token)
      const res = await fetch(act.object.url, {
        headers: {
          Authorization: `Bearer ${token2}`
        }
      })
      assert.strictEqual(res.status, 403)
    })
  })

  describe('Create a collection', () => {
    let actor = null
    let token = null
    let note1 = null
    let note2 = null
    let withItems = null
    let noItems = null

    before(async () => {
      [actor, token] = await registerActor()
      const createNote = await doActivity(actor, token, {
        type: 'Create',
        to: [PUBLIC],
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, World!'
          }
        }
      })
      note1 = createNote.object
      const createNote2 = await doActivity(actor, token, {
        type: 'Create',
        to: [PUBLIC],
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, World, again!'
          }
        }
      })
      note2 = createNote2.object
      withItems = (
        await doActivity(actor, token, {
          type: 'Create',
          to: [PUBLIC],
          object: {
            type: 'Collection',
            items: [note1.id]
          }
        })
      ).object
      noItems = (
        await doActivity(actor, token, {
          type: 'Create',
          to: [PUBLIC],
          object: {
            type: 'Collection'
          }
        })
      ).object
    })

    it('can get a collection with items', async () => {
      const collection = await getObject(withItems.id, token)
      assert.ok(collection.items)
      assert.strictEqual(collection.items.length, 1)
      assert.strictEqual(collection.items[0].id, note1.id)
    })

    it('can get a collection without items', async () => {
      const collection = await getObject(noItems.id, token)
      assert.ok(collection)
      assert.ok(collection.first)
      const collectionPage = await getObject(collection.first.id, token)
      assert.ok(collectionPage)
      assert.ok(collectionPage.items)
      assert.strictEqual(collectionPage.items.length, 0)
    })

    it('can add an item to an initialized collection', async () => {
      await doActivity(actor, token, {
        type: 'Add',
        object: note2.id,
        target: withItems.id
      })
      assert.ok(await isInStream(withItems, note2, token))
    })

    it('can remove an item from an initialized collection', async () => {
      await doActivity(actor, token, {
        type: 'Remove',
        object: note2.id,
        target: withItems.id
      })
      assert.ok(!(await isInStream(withItems, note2, token)))
    })

    it('can add an item to an uninitialized collection', async () => {
      await doActivity(actor, token, {
        type: 'Add',
        object: note2.id,
        target: noItems.id
      })
      assert.ok(await isInStream(noItems, note2, token))
    })

    it('can remove an item from an uninitialized collection', async () => {
      await doActivity(actor, token, {
        type: 'Remove',
        object: note2.id,
        target: noItems.id
      })
      assert.ok(!(await isInStream(noItems, note2, token)))
    })
  })

  describe('Inbox overflow', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let firstAct = null
    let lastAct = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor()
      firstAct = await doActivity(actor2, token2, {
        to: [actor1.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: `Hello, ${actor1.name}! first`
          }
        }
      })
      await settle(MAIN_PORT)
      for (let i = 0; i < 23; i++) {
        await doActivity(actor2, token2, {
          to: [actor1.id],
          type: 'Create',
          object: {
            type: 'Note',
            contentMap: {
              en: `Hello, ${actor1.name}! ${i}`
            }
          }
        })
      }
      await settle(MAIN_PORT)
      lastAct = await doActivity(actor2, token2, {
        to: [actor1.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: `Hello, ${actor1.name}! last`
          }
        }
      })
      await settle(MAIN_PORT)
    })
    it('actor has items in the inbox', async () => {
      const inbox = await getObject(actor1.inbox, token1)
      assert.strictEqual(inbox.totalItems, 25)
    })
    it('first page in the inbox has members', async () => {
      const inbox = await getObject(actor1.inbox, token1)
      const firstPage = await getObject(inbox.first.id, token1)
      assert.ok(firstPage.orderedItems)
      assert.strictEqual(firstPage.orderedItems.length, 5)
    })
    it('last page in the inbox has members', async () => {
      const inbox = await getObject(actor1.inbox, token1)
      const lastPage = await getObject(inbox.last.id, token1)
      assert.ok(lastPage.orderedItems)
      assert.strictEqual(lastPage.orderedItems.length, 20)
      assert.strictEqual(lastPage.orderedItems[19].id, firstAct.id)
    })
    it('first activity is in the inbox', async () => {
      assert.ok(await isInStream(actor1.inbox, firstAct, token1))
    })
    it('last activity is in the inbox', async () => {
      assert.ok(await isInStream(actor1.inbox, lastAct, token1))
    })
  })

  describe('Create copies addressees to object', () => {
    let actor1 = null
    let token1 = null
    let note = null

    before(async () => {
      [actor1, token1] = await registerActor()
      const create = await doActivity(actor1, token1, {
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, World!'
          }
        }
      })
      note = create.object
      await settle(MAIN_PORT)
    })

    it('note has addressees', async () => {
      assert.ok(note.to)
      assert.strictEqual(note.to.length, 1)
      assert.strictEqual(note.to[0].id, PUBLIC)
    })

    it('retrieved has addressees', async () => {
      const retrieved = await getObject(note.id, token1)
      assert.ok(retrieved.to)
      assert.strictEqual(retrieved.to.length, 1)
      assert.strictEqual(retrieved.to[0].id, PUBLIC)
    })
  })

  describe('Create copies addressees from object', () => {
    let actor1 = null
    let token1 = null
    let create = null

    before(async () => {
      [actor1, token1] = await registerActor()
      create = await doActivity(actor1, token1, {
        type: 'Create',
        object: {
          to: [PUBLIC],
          type: 'Note',
          contentMap: {
            en: 'Hello, World!'
          }
        }
      })
      await settle(MAIN_PORT)
    })

    it('create has addressees', async () => {
      assert.ok(create.to)
      assert.strictEqual(create.to.length, 1)
      assert.strictEqual(create.to[0].id, PUBLIC)
    })

    it('retrieved has addressees', async () => {
      const retrieved = await getObject(create.id, token1)
      assert.ok(retrieved.to)
      assert.strictEqual(retrieved.to.length, 1)
      assert.strictEqual(retrieved.to[0].id, PUBLIC)
    })
  })

  describe('Like uncached object', () => {
    let actor1 = null
    let token1 = null
    let actor2 = null
    let token2 = null
    let note = null
    let like = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [actor2, token2] = await registerActor(REMOTE_PORT)
      const create = await doActivity(actor1, token1, {
        to: [PUBLIC],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, World!'
          }
        }
      })
      note = create.object
      await settle(MAIN_PORT)
      like = await doActivity(actor2, token2, {
        to: [actor1.id],
        cc: [PUBLIC],
        type: 'Like',
        object: note.id
      })
      await settle(REMOTE_PORT)
    })
    it('note is in liked collection', async () => {
      assert.ok(await isInStream(actor2.liked, note, token2))
    })
    it('activity is in likes collection', async () => {
      assert.ok(await isInStream(note.likes, like, token1))
    })
  })

  describe('Root object public key', () => {
    it('Root object has a valid key', async () => {
      const id = `https://localhost:${MAIN_PORT}/`
      const res = await fetch(`https://localhost:${MAIN_PORT}/`, {
        headers: {
          Accept:
            'application/activity+json,application/ld+json,application/json'
        }
      })
      const obj = await res.json()
      assert(res.ok)
      assert(obj.publicKey)
      assert.strictEqual(typeof obj.publicKey, 'object')
      assert.strictEqual(typeof obj.publicKey.id, 'string')
      assert.strictEqual(typeof obj.publicKey.type, 'string')
      assert.strictEqual(obj.publicKey.type, 'CryptographicKey')
      assert.strictEqual(typeof obj.publicKey.owner, 'string')
      assert.strictEqual(obj.publicKey.owner, id)
      assert.strictEqual(typeof obj.publicKey.publicKeyPem, 'string')
      assert.match(obj.publicKey.publicKeyPem, /^-----BEGIN PUBLIC KEY-----/)
    })
    it('Root object key can be retrieved', async () => {
      const id = `https://localhost:${MAIN_PORT}/`
      const res = await fetch(id, {
        headers: {
          Accept:
            'application/activity+json,application/ld+json,application/json'
        }
      })
      assert(res.ok)
      const obj = await res.json()
      assert(obj.publicKey)
      assert(obj.publicKey.id)
      const keyId = obj.publicKey.id
      const keyRes = await fetch(keyId, {
        headers: {
          Accept:
            'application/activity+json,application/ld+json,application/json'
        }
      })
      assert(keyRes.ok)
      const keyObj = await keyRes.json()
      assert.strictEqual(typeof keyObj, 'object')
      assert.strictEqual(typeof keyObj.id, 'string')
      assert.strictEqual(keyObj.id, keyId)
      assert.strictEqual(typeof keyObj.type, 'string')
      assert.strictEqual(keyObj.type, 'CryptographicKey')
      assert.strictEqual(typeof keyObj.owner, 'string')
      assert.strictEqual(keyObj.owner, id)
      assert.strictEqual(typeof keyObj.publicKeyPem, 'string')
      assert.match(keyObj.publicKeyPem, /^-----BEGIN PUBLIC KEY-----/)
    })
  })

  describe('Actor has webfinger property', () => {
    let actor1 = null
    before(async () => {
      [actor1] = await registerActor()
    })
    it('Actor has webfinger property', async () => {
      const obj = await getObject(actor1.id)
      assert.strictEqual(typeof obj, 'object')
      assert('@context' in obj)
      assert(Array.isArray(obj['@context']))
      assert(
        obj['@context'].includes(
          'https://purl.archive.org/socialweb/webfinger'
        )
      )
      assert('webfinger' in obj)
      assert.strictEqual(typeof obj.webfinger, 'string')
      assert.strictEqual(
        obj.webfinger,
        `${actor1.preferredUsername}@localhost:${MAIN_PORT}`
      )
    })
  })

  describe('Actor has miscellany context', () => {
    let actor1 = null
    before(async () => {
      [actor1] = await registerActor()
    })
    it('Actor has miscellany context', async () => {
      const obj = await getObject(actor1.id)
      assert.strictEqual(typeof obj, 'object')
      assert('@context' in obj)
      assert(Array.isArray(obj['@context']))
      assert(
        obj['@context'].includes(
          'https://purl.archive.org/socialweb/miscellany'
        )
      )
    })
  })

  describe('Actor has CORS headers', () => {
    let actor1 = null
    before(async () => {
      [actor1] = await registerActor()
    })
    it('Actor has CORS headers', async () => {
      const headers = {
        accept: 'application/activity+json'
      }
      const res = await fetch(actor1.id, {
        headers
      })
      assert.strictEqual(200, res.status)
      assert.strictEqual(res.headers.get('Access-Control-Allow-Origin'), '*')
    })
  })

  describe('@context is first property', () => {
    let actor1 = null
    before(async () => {
      [actor1] = await registerActor()
    })
    it('@context is first property', async () => {
      const headers = {
        accept: 'application/activity+json'
      }
      const res = await fetch(actor1.id, {
        headers
      })
      assert.strictEqual(200, res.status)
      const output = await res.text()
      assert.match(output, /^{\s*"@context":/)
    })
  })

  describe('User collections have correct addressees', () => {
    let actor1 = null
    let token1 = null
    let token2 = null
    let outbox = null
    before(async () => {
      [actor1, token1] = await registerActor();
      [, token2] = await registerActor()
      for (let i = 0; i < 23; i++) {
        await doActivity(actor1, token1, {
          to: [PUBLIC],
          type: 'Create',
          object: {
            type: 'Note',
            contentMap: {
              en: `Hello, World! (iteration ${i})`
            }
          }
        })
      }
      await settle(MAIN_PORT)
    })
    it('Collection has correct addressees', async () => {
      outbox = await getObject(actor1.outbox, token1)
      assert.strictEqual(outbox.to.length, 1)
      assert.strictEqual(outbox.to[0].id, PUBLIC)
    })
    it('First collection page has correct addressees', async () => {
      const firstPage = await getObject(outbox.first.id, token1)
      assert.strictEqual(firstPage.to.length, 1)
      assert.strictEqual(firstPage.to[0].id, PUBLIC)
    })
    it('Last collection page has correct addressees', async () => {
      const firstPage = await getObject(outbox.last.id, token1)
      assert.strictEqual(firstPage.to.length, 1)
      assert.strictEqual(firstPage.to[0].id, PUBLIC)
    })
    it('Other actor can get outbox', async () => {
      const outbox = await getObject(actor1.outbox, token2)
      assert.strictEqual(outbox.totalItems, 23)
    })
    it('Other actor can get first outbox page', async () => {
      const outbox = await getObject(actor1.outbox, token2)
      const firstPage = await getObject(outbox.first.id, token2)
      assert.ok(firstPage)
    })
    it('Other actor can get last outbox page', async () => {
      const outbox = await getObject(actor1.outbox, token2)
      const lastPage = await getObject(outbox.last.id, token2)
      assert.ok(lastPage)
    })
    it('Unauthenticated user can get outbox', async () => {
      const outbox = await getObject(actor1.outbox)
      assert.strictEqual(outbox.totalItems, 23)
    })
    it('Unauthenticated user can get first outbox page', async () => {
      const outbox = await getObject(actor1.outbox)
      const firstPage = await getObject(outbox.first.id)
      assert.ok(firstPage)
    })
    it('Unauthenticated user can get last outbox page', async () => {
      const outbox = await getObject(actor1.outbox)
      const lastPage = await getObject(outbox.last.id)
      assert.ok(lastPage)
    })
  })
})
