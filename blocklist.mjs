import 'dotenv/config'
import { describe, before, after, it } from 'node:test'
import { spawn } from 'node:child_process'
import assert from 'node:assert'
import querystring from 'node:querystring'
import crypto from 'node:crypto'
import https from 'node:https'
import fs from 'node:fs'
import { promisify } from 'node:util'

// remove temporary database on startup if it exists
if (fs.existsSync('temp.sqlite')) {
  fs.unlink('temp.sqlite', (err) => {
    if (err) {
      console.log(err)
    } else {
      console.log('Old database deleted successfully')
    }
  })
}

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0

const MAIN_PORT = 50941 // V
const REMOTE_PORT = 52998 // Cr
const CLIENT_PORT = 54938 // Mn
const FOURTH_PORT = 58933 // Co

const CLIENT_ID = `https://localhost:${CLIENT_PORT}/client`
const REDIRECT_URI = `https://localhost:${CLIENT_PORT}/oauth/callback`
const AS2 = 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"'
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
  '@context': [
    AS2_CONTEXT,
    'https://purl.archive.org/socialweb/oauth'
  ],
  type: 'Application',
  id: CLIENT_ID,
  redirectURI: REDIRECT_URI,
  nameMap: {
    en: 'Test scripts for onepage.pub'
  }
}

const startClientServer = (port = CLIENT_PORT, client = JSON.stringify(defaultClient), contentType = AS2) => {
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

/**
 * Posts an activity to the given actor's outbox.
 * 
 * @param {Object} actor - The actor object
 * @param {string} token - The authentication token
 * @param {Object} activity - The activity object to post
 * @returns {Promise<Object>} - Promise resolving to the posted activity response
 */
const doActivity = async (actor, token, activity) => {
  const res = await fetch(actor.outbox, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
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
      'Content-Type': 'application/ld+json; profile="https://www.w3.org/ns/activitystreams"',
      Authorization: `Bearer ${token}`
    },
    body: JSON.stringify(activity)
  })
  const body = await res.text()
  if (res.status >= 200 && res.status <= 299) {
    throw new Error(`Good status code ${res.status} for activity that should fail: ${body}`)
  }
  return res.status
}

const getObject = async (id, token = null) => {
  const headers = {
    Accept: 'application/ld+json; profile="https://www.w3.org/ns/activitystreams",application/activity+json,application/json'
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
    throw new Error(`Invalid collection ${url}: no items, orderedItems, or first`)
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

/**
 * Checks if a proxy can be retrieved for the given ID using the provided actor and token.
 * 
 * @param {string} id - The ID to attempt to get a proxy for
 * @param {object} actor - The actor object with API endpoints
 * @param {string} token - The access token to use for the API request
 * @returns {boolean} True if a proxy object could be retrieved, false otherwise
 */
const canGetProxy = async (id, actor, token) => {
  const result = await getProxy(id, actor, token)
  return !!result
}

const getAuthCode = async (actor, cookie, scope = 'read write') => {
  const state = crypto.randomBytes(16).toString('hex')
  const authz = actor.endpoints.oauthAuthorizationEndpoint
  const responseType = 'code'
  const codeVerifier = crypto.randomBytes(32).toString('hex')
  const codeChallenge = base64URLEncode(crypto.createHash('sha256').update(codeVerifier).digest())
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
  str.toString('base64')
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

async function signRequest (keyId, privateKey, method, url, date) {
  url = (typeof url === 'string') ? new URL(url) : url
  const target = (url.search && url.search.length)
    ? `${url.pathname}?${url.search}`
    : `${url.pathname}`
  let data = `(request-target): ${method.toLowerCase()} ${target}\n`
  data += `host: ${url.host}\n`
  data += `date: ${date}`
  const signer = crypto.createSign('sha256')
  signer.update(data)
  const signature = signer.sign(privateKey).toString('base64')
  signer.end()
  const header = `keyId="${keyId}",headers="(request-target) host date",signature="${signature.replace(/"/g, '\\"')}",algorithm="rsa-sha256"`
  return header
}

describe('onepage.pub', () => {
  let child = null
  let remote = null
  let client = null

  // use temporary database for testing 
  process.env.OPP_DATABASE = "temp.sqlite"
  // increase rate limit for testing
  process.env.OPP_RATE_LIMIT = "100000"

  before(async () => {
    console.log('Starting servers')
    child = await startServer(MAIN_PORT)
    remote = await startServer(REMOTE_PORT)
    client = await startClientServer(CLIENT_PORT)
  })

  after(() => {
    console.log('Stopping servers')
    child.kill('SIGTERM')
    remote.kill('SIGTERM')
    client.close()
    console.log('finished running tests')
  })

  describe('Blocklist file', () => {
    let [actor1, token1] = [null, null]
    let [actor2, token2] = [null, null]
    let [actor3, token3] = [null, null]
    let server = null
    let created = null
    before(async () => {
      server = await startServer(process.env.OPP_PORT, {});
      
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
      assert.ok(!await isInStream(actor3.inbox, activity, token3))
    })
    

    
    it('will accept read from unblocked', async () => {
      assert.ok(await canGetProxy(created.object.id, actor1, token1))
    })

    it('will not accept read from blocked', async () => {
      assert.ok(!await canGetProxy(created.object.id, actor2, token2))
    })
    
  })
})
