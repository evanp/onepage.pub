import { describe, before, after, it } from 'node:test'
import { exec } from 'node:child_process'
import assert from 'node:assert'
import querystring from 'node:querystring'
import { inspect } from 'node:util'
import crypto from 'node:crypto'

process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0

const clientId = 'https://test.onepage.pub'
const redirectUri = 'https://test.onepage.pub/oauth/callback'

const delay = (t) => new Promise((resolve) => setTimeout(resolve, t))

const startServer = (port = 3000) => {
  return new Promise((resolve, reject) => {
    const server = exec(`OPP_PORT=${port} node index.mjs`)
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

const registerUser = (() => {
  let i = 100
  return async (port = 3000) => {
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

const registerActor = async (port = 3000) => {
  const [username, token, , cookie] = await registerUser(port)
  const res = await fetch(
    `https://localhost:${port}/.well-known/webfinger?resource=acct:${username}@localhost:${port}`
  )
  const obj = await res.json()
  const actorId = obj.links[0].href
  const actorRes = await fetch(actorId)
  const actor = await actorRes.json()
  return [actor, token, cookie]
}

const doActivity = async (actor, token, activity) => {
  const res = await fetch(actor.outbox.id, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/activity+json',
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
  const res = await fetch(actor.outbox.id, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/activity+json',
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
  const res = await fetch(id, {
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  })
  if (res.status !== 200) {
    throw new Error(`Bad status code ${res.status}`)
  }
  return await res.json()
}

const getMembers = async (collection, token = null) => {
  if (!collection || !collection.id) {
    throw new Error(`Invalid collection: ${inspect(collection)}`)
  }
  const coll = await getObject(collection.id, token)
  let members = []
  for (let page = coll.first; page; page = page.next) {
    const pageObj = await getObject(page.id, token)
    for (const prop of ['orderedItems', 'items']) {
      if (pageObj[prop]) {
        members = members.concat(pageObj[prop])
      }
    }
  }
  return members
}

const isInStream = async (collection, object, token = null) => {
  const members = await getMembers(collection, token)
  return members.some((item) => item.id === object.id)
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
  const codeChallenge = base64URLEncode(crypto.createHash('sha256').update(codeVerifier).digest())
  const qs = querystring.stringify({
    response_type: responseType,
    client_id: clientId,
    redirect_uri: redirectUri,
    scope,
    state,
    code_challenge_method: 'S256',
    code_challenge: codeChallenge
  })
  const res = await fetch(`${authz}?${qs}`, {
    headers: { Cookie: cookie }
  })
  const body = await res.text()
  const action = body.match(/action="(.+?)"/)[1]
  const csrfToken = body.match(/name="csrf_token" value="(.+?)"/)[1]
  const post = new URL(action, authz)
  const res2 = await fetch(post, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Cookie: cookie
    },
    body: querystring.stringify({
      csrf_token: csrfToken,
      client_id: clientId,
      redirect_uri: redirectUri,
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
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
      client_id: clientId
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

describe('onepage.pub', { only: true }, () => {
  let child = null
  let remote = null

  before(async () => {
    child = await startServer(3000)
    remote = await startServer(3001)
  })

  after(() => {
    child.kill()
    remote.kill()
  })

  describe('Root object', () => {
    it('can get the root object', async () => {
      const res = await fetch('https://localhost:3000/')
      const obj = await res.json()
      assert.strictEqual(obj.type, 'Service')
      assert.strictEqual(obj.name, 'One Page Pub')
      assert.strictEqual(obj.id, 'https://localhost:3000/')
    })
  })

  describe('Registration', () => {
    it('can get a registration form', async () => {
      const res = await fetch('https://localhost:3000/register')
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
      const res = await fetch('https://localhost:3000/register', {
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
        `https://localhost:3000/.well-known/webfinger?resource=acct:${username}@localhost:3000`
      )
      if (res.status !== 200) {
        const body = await res.text()
        console.log(body)
      }
      assert.strictEqual(res.status, 200)
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'application/jrd+json; charset=utf-8'
      )
      const obj = await res.json()
      assert.strictEqual(obj.subject, `acct:${username}@localhost:3000`)
      assert.strictEqual(obj.links[0].rel, 'self')
      assert.strictEqual(obj.links[0].type, 'application/activity+json')
      assert(obj.links[0].href.startsWith('https://localhost:3000/person/'))
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
        `https://localhost:3000/.well-known/webfinger?resource=acct:${username}@localhost:3000`
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
      assert.strictEqual(
        actorRes.headers.get('Content-Type'),
        'application/activity+json; charset=utf-8'
      )
    })

    it('has the as2 @context', () => {
      assert(actorObj['@context'])
      assert.notEqual(
        -1,
        actorObj['@context'].indexOf('https://www.w3.org/ns/activitystreams')
      )
    })

    it('has the security @context', () => {
      assert(actorObj['@context'])
      assert.notEqual(
        -1,
        actorObj['@context'].indexOf('https://w3id.org/security')
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
      assert.equal('object', typeof actorObj.inbox)
      assert.equal('string', typeof actorObj.inbox.id)
      assert(
        actorObj.inbox.id.startsWith(
          'https://localhost:3000/orderedcollection/'
        )
      )
    })

    it('has a valid outbox', () => {
      assert.equal('object', typeof actorObj.outbox)
      assert.equal('string', typeof actorObj.outbox.id)
      assert(
        actorObj.outbox.id.startsWith(
          'https://localhost:3000/orderedcollection/'
        )
      )
    })

    it('has a valid followers', () => {
      assert.equal('object', typeof actorObj.followers)
      assert.equal('string', typeof actorObj.followers.id)
      assert(
        actorObj.followers.id.startsWith(
          'https://localhost:3000/orderedcollection/'
        )
      )
    })

    it('has a valid following', () => {
      assert.equal('object', typeof actorObj.following)
      assert.equal('string', typeof actorObj.following.id)
      assert(
        actorObj.following.id.startsWith(
          'https://localhost:3000/orderedcollection/'
        )
      )
    })

    it('has a valid liked', () => {
      assert.equal('object', typeof actorObj.liked)
      assert.equal('string', typeof actorObj.liked.id)
      assert(
        actorObj.liked.id.startsWith(
          'https://localhost:3000/orderedcollection/'
        )
      )
    })

    it('has a blocked property', () => {
      assert.equal('object', typeof actorObj.blocked)
      assert.equal('string', typeof actorObj.blocked.id)
      assert(
        actorObj.blocked.id.startsWith(
          'https://localhost:3000/orderedcollection/'
        )
      )
    })

    it('has a pendingFollowers property', () => {
      assert.equal('object', typeof actorObj.pendingFollowers)
      assert.equal('string', typeof actorObj.pendingFollowers.id)
      assert(
        actorObj.blocked.id.startsWith(
          'https://localhost:3000/orderedcollection/'
        )
      )
    })

    it('has a pendingFollowing property', () => {
      assert.equal('object', typeof actorObj.pendingFollowing)
      assert.equal('string', typeof actorObj.pendingFollowing.id)
      assert(
        actorObj.blocked.id.startsWith(
          'https://localhost:3000/orderedcollection/'
        )
      )
    })

    it('has a public key', () => {
      assert(actorObj.publicKey)
      assert.equal('object', typeof actorObj.publicKey)
      assert.equal('string', typeof actorObj.publicKey.id)
      assert(actorObj.publicKey.id.startsWith('https://localhost:3000/key/'))
      assert.equal('string', typeof actorObj.publicKey.type)
      assert.equal('Key', actorObj.publicKey.type)
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
      const res = await fetch(actor.inbox.id)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'application/activity+json; charset=utf-8'
      )
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.inbox.id)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith('https://localhost:3000/orderedcollectionpage/')
      )
    })
    it('can get actor outbox', async () => {
      const res = await fetch(actor.outbox.id)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'application/activity+json; charset=utf-8'
      )
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.outbox.id)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith('https://localhost:3000/orderedcollectionpage/')
      )
    })
    it('can get actor followers', async () => {
      const res = await fetch(actor.followers.id)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'application/activity+json; charset=utf-8'
      )
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.followers.id)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith('https://localhost:3000/orderedcollectionpage/')
      )
    })
    it('can get actor following', async () => {
      const res = await fetch(actor.following.id)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'application/activity+json; charset=utf-8'
      )
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.following.id)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith('https://localhost:3000/orderedcollectionpage/')
      )
    })
    it('can get actor liked', async () => {
      const res = await fetch(actor.liked.id)
      assert.strictEqual(res.status, 200)
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'application/activity+json; charset=utf-8'
      )
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.liked.id)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith('https://localhost:3000/orderedcollectionpage/')
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
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'application/activity+json; charset=utf-8'
      )
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.blocked.id)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith('https://localhost:3000/orderedcollectionpage/')
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
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'application/activity+json; charset=utf-8'
      )
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.pendingFollowers.id)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith('https://localhost:3000/orderedcollectionpage/')
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
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'application/activity+json; charset=utf-8'
      )
      const obj = await res.json()
      assert.strictEqual(obj.id, actor.pendingFollowing.id)
      assert.strictEqual(obj.type, 'OrderedCollection')
      assert.strictEqual(obj.totalItems, 0)
      assert(obj.nameMap?.en)
      assert(obj.first)
      assert(
        obj.first.id.startsWith('https://localhost:3000/orderedcollectionpage/')
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
      '@context': 'https://www.w3.org/ns/activitystreams',
      type: 'IntransitiveActivity',
      to: 'https://www.w3.org/ns/activitystreams#Public'
    }

    before(async () => {
      [actor, token] = await registerActor()
      res = await fetch(actor.outbox.id, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/activity+json; charset=utf-8',
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
      assert.strictEqual(
        res.headers.get('Content-Type'),
        'application/activity+json; charset=utf-8'
      )
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
      const inbox = await (await fetch(actor.inbox.id)).json()
      const inboxPage = await (await fetch(inbox.first.id)).json()
      assert(inboxPage.orderedItems.some((act) => act.id === obj.id))
    })

    it("appears in the actor's outbox", async () => {
      const outbox = await (await fetch(actor.outbox.id)).json()
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'IntransitiveActivity',
        to: [actor1.id]
      }
      const res = await fetch(actor1.outbox.id, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/activity+json; charset=utf-8',
          Authorization: `Bearer ${token1}`
        },
        body: JSON.stringify(input)
      })
      const body = await res.text()
      activity = JSON.parse(body)
    })

    it('author can see own private activity', async () => {
      const outbox = await (
        await fetch(actor1.outbox.id, {
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
        await fetch(actor1.outbox.id, {
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
      [actor1, token1] = await registerActor(3000);
      [actor2, token2] = await registerActor(3001)
    })

    it('sends to remote addressees', async () => {
      const activity = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'IntransitiveActivity',
        to: actor2.id
      }
      const res = await fetch(actor1.outbox.id, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/activity+json; charset=utf-8',
          Authorization: `Bearer ${token1}`
        },
        body: JSON.stringify(activity)
      })
      const body = await res.text()
      const obj = JSON.parse(body)
      await delay(100)
      const inbox = await (
        await fetch(actor2.inbox.id, {
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'IntransitiveActivity',
        to: actor1.id
      }
      const res = await fetch(actor2.outbox.id, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/activity+json; charset=utf-8',
          Authorization: `Bearer ${token2}`
        },
        body: JSON.stringify(activity)
      })
      const body = await res.text()
      const obj = JSON.parse(body)
      // Wait for delivery!
      await delay(100)
      const inbox = await (
        await fetch(actor1.inbox.id, {
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
    })

    it("puts the actor in the other's followers", async () => {
      assert(await isInStream(actor2.followers, actor1, token2))
    })

    it("puts the other in the actor's following", async () => {
      assert(await isInStream(actor1.following, actor2, token1))
    })

    it('distributes to the actor when the other posts to followers', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.followers.id,
        type: 'Note',
        contentMap: {
          en: 'Hello, world!'
        }
      })
      assert(await isInStream(actor1.inbox, createNote, token1))
    })

    it('distributes to the actor when the other posts to public', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: 'https://www.w3.org/ns/activitystreams#Public',
        type: 'Note',
        contentMap: {
          en: 'Hello, world!'
        }
      })
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'Reject',
        object: follow.id
      })
    })

    it("does not appear in the actor's pending following", async () => {
      assert(!await isInStream(actor1.pendingFollowing, follow, token1))
    })

    it("does not appear in the other's pending followers", async () => {
      assert(!await isInStream(actor2.pendingFollowers, follow, token2))
    })

    it("does not put the actor in the other's followers", async () => {
      assert(!(await isInStream(actor2.followers, actor1, token2)))
    })

    it("does not put the other in the actor's following", async () => {
      assert(!(await isInStream(actor1.following, actor2, token1)))
    })

    it('does not distribute to the actor when the other posts to followers', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.followers.id,
        type: 'Note',
        contentMap: {
          en: 'Hello, world!'
        }
      })
      assert(!(await isInStream(actor1.inbox, createNote, token1)))
    })

    it('does not distribute to the actor when the other posts to public', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: 'https://www.w3.org/ns/activitystreams#Public',
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'Create',
        object: {
          type: 'Note',
          content
        }
      }
      const res = await fetch(actor1.outbox.id, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/activity+json; charset=utf-8',
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'Create',
        object: {
          type: 'Note',
          content
        }
      }
      const res = await fetch(actor1.outbox.id, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/activity+json; charset=utf-8',
          Authorization: `Bearer ${token1}`
        },
        body: JSON.stringify(source)
      })
      created = await res.json()
      const updateSource = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'Update',
        object: {
          id: created.object.id,
          content: null,
          contentMap
        }
      }
      const updateRes = await fetch(actor1.outbox.id, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/activity+json; charset=utf-8',
          Authorization: `Bearer ${token1}`
        },
        body: JSON.stringify(updateSource)
      })
      updated = await updateRes.json()
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'Create',
        object: {
          type: 'Note',
          content: 'My dog has fleas.'
        }
      }
      const res = await fetch(actor1.outbox.id, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/activity+json; charset=utf-8',
          Authorization: `Bearer ${token1}`
        },
        body: JSON.stringify(source)
      })
      created = await res.json()
      const deleteSource = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'Delete',
        object: created.object.id
      }
      const deleteRes = await fetch(actor1.outbox.id, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/activity+json; charset=utf-8',
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Buy some milk'
          }
        }
      })
      createdCollection = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
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
        '@context': 'https://www.w3.org/ns/activitystreams',
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Buy some milk'
          }
        }
      })
      createdNote2 = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Clean the garage'
          }
        }
      })
      createdCollection = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'Add',
        object: createdNote1.object.id,
        target: createdCollection.object.id
      })
      await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'Add',
        object: createdNote2.object.id,
        target: createdCollection.object.id
      })
      await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'My dog has fleas.'
          }
        }
      })
      liked = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
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
      const likedStream = await (await fetch(actor2.liked.id)).json()
      const likedPage = await (await fetch(likedStream.first.id)).json()
      assert(
        likedPage.orderedItems.some((obj) => obj.id === createdNote1.object.id)
      )
    })

    it("actor's liked count is 1", async () => {
      const likedStream = await (await fetch(actor2.liked.id)).json()
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'Follow',
        object: actor1.id
      })
      await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
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
      const followersStream = await (await fetch(actor1.followers.id)).json()
      const followersPage = await (
        await fetch(followersStream.first.id)
      ).json()
      assert(
        followersPage.orderedItems.every((actor) => actor.id !== actor2.id)
      )
    })

    it("actor does not appear in the other's following", async () => {
      const followingStream = await (await fetch(actor2.following.id)).json()
      const followingPage = await (
        await fetch(followingStream.first.id)
      ).json()
      assert(
        followingPage.orderedItems.every((actor) => actor.id !== actor1.id)
      )
    })

    it("other can't send to actor", async () => {
      const created = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
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
        await fetch(actor1.inbox.id, {
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: 'https://www.w3.org/ns/activitystreams#Public',
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Here are my thoughts.'
          }
        }
      })
      const res = await fetch(actor2.outbox.id, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token2}`,
          'Content-Type': 'application/activity+json'
        },
        body: JSON.stringify({
          '@context': 'https://www.w3.org/ns/activitystreams',
          to: 'https://www.w3.org/ns/activitystreams#Public',
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
      const res = await fetch(actor1.outbox.id, {
        headers: { Authorization: `Bearer ${token2}` }
      })
      assert.strictEqual(res.status, 403)
    })

    it("other can't read actor note", async () => {
      const created = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: 'https://www.w3.org/ns/activitystreams#Public',
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello world!'
          }
        }
      })
      createReply = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello world!'
          }
        }
      })
      announce = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello world!'
          }
        }
      })
      like = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Like',
        object: createNote.object.id
      })
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Undo',
        object: like.id
      })
    })

    it("object is not in actor's liked", async () => {
      const likedStream = await (
        await fetch(actor2.liked.id, {
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Block',
        object: actor2.id
      })
      createNote = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello world!'
          }
        }
      })
      await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'Follow',
        object: actor1.id
      })
      assert(follow.id)
    })

    it('other can reply to actor', async () => {
      const reply = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello world!'
          }
        }
      })
      await delay(100)
      assert(!(await isInStream(actor1.inbox, createPublic, token1)))
    })

    it('actor does not receive followers-only posts', async () => {
      const createFollowersOnly = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor2.followers.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello world!'
          }
        }
      })
      await delay(100)
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
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
      [actor2, token2] = await registerActor(3001)
      follow = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await delay(100)
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
      [actor2, token2] = await registerActor(3001)
      follow = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await delay(100)
    })

    it("removes the follow from the actor's pending following", async () => {
      assert(!await isInStream(actor1.pendingFollowing, follow, token1))
    })

    it("removes the follow from the other's pending followers", async () => {
      assert(!await isInStream(actor2.pendingFollowers, follow, token2))
    })

    it("puts the actor in the other's followers", async () => {
      assert(await isInStream(actor2.followers, actor1, token2))
    })

    it("puts the other in the actor's following", async () => {
      assert(await isInStream(actor1.following, actor2, token1))
    })

    it('distributes to the actor when the other posts to followers', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.followers.id,
        type: 'Note',
        contentMap: {
          en: 'Hello, world!'
        }
      })
      await delay(100)
      assert(await isInStream(actor1.inbox, createNote, token1))
    })

    it('distributes to the actor when the other posts to public', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: 'https://www.w3.org/ns/activitystreams#Public',
        type: 'Note',
        contentMap: {
          en: 'Hello, world!'
        }
      })
      await delay(100)
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
      [actor2, token2] = await registerActor(3001)
      follow = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor1.id,
        type: 'Reject',
        object: follow.id
      })
      await delay(100)
    })

    it("does not appear in the actor's pending following", async () => {
      assert(!await isInStream(actor1.pendingFollowing, follow, token1))
    })

    it("does not appear in the other's pending followers", async () => {
      assert(!await isInStream(actor2.pendingFollowers, follow, token2))
    })

    it("does not put the actor in the other's followers", async () => {
      assert(!(await isInStream(actor2.followers, actor1, token2)))
    })

    it("does not put the other in the actor's following", async () => {
      assert(!(await isInStream(actor1.following, actor2, token1)))
    })

    it('does not distribute to the actor when the other posts to followers', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.followers.id,
        type: 'Note',
        contentMap: {
          en: 'Hello, world!'
        }
      })
      await delay(100)
      assert(!(await isInStream(actor1.inbox, createNote, token1)))
    })

    it('does not distribute to the actor when the other posts to public', async () => {
      const createNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: 'https://www.w3.org/ns/activitystreams#Public',
        type: 'Note',
        contentMap: {
          en: 'Hello, world!'
        }
      })
      await delay(100)
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
      [actor2, token2] = await registerActor(3001);
      [actor3, token3] = await registerActor()
      follow = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await delay(100)
      pub = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      priv = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor2.followers.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, followers!'
          }
        }
      })
      self = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor2.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, self!'
          }
        }
      })
      await delay(100)
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
      assert(!await canGetProxy(self.object.id, actor1, token1))
    })

    it('random can get public note through proxy', async () => {
      assert(await canGetProxy(pub.object.id, actor3, token3))
    })

    it('random cannot get private note through proxy', async () => {
      assert(!await canGetProxy(priv.object.id, actor3, token3))
    })

    it('random cannot get followers-only note through proxy', async () => {
      assert(!await canGetProxy(followers.object.id, actor3, token3))
    })

    it('random cannot get self-only note through proxy', async () => {
      assert(!await canGetProxy(self.object.id, actor3, token3))
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
      [actor2, token2] = await registerActor(3001)
      follow = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await delay(100)
      createNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor2.followers.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await delay(100)
      createReply = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor2.id, actor2.followers.id],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, back!'
          },
          inReplyTo: createNote.object.id
        }
      })
      await delay(100)
    })

    it("note appears in the actor's inbox", async () => {
      assert(await isInStream(actor1.inbox, createNote, token1))
    })

    it("reply appears in other's inbox", async () => {
      assert(await isInStream(actor2.inbox, createReply, token2))
    })

    it("reply appears in original note's replies", async () => {
      assert(await isInStream(createNote.object.replies, createReply.object, token2))
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
      [actor2, token2] = await registerActor(3001)
      follow = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await delay(100)
      createNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await delay(100)
      updateNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Update',
        object: {
          id: createNote.object.id,
          contentMap: {
            en: 'Hello, world! (updated)'
          }
        }
      })
      await delay(100)
    })

    it('correct value in proxy', async () => {
      const note = await getProxy(createNote.object.id, actor1, token1)
      assert.equal(note.contentMap.en, 'Hello, world! (updated)')
    })

    it('correct value for update in inbox', async () => {
      const activities = await getMembers(actor1.inbox, token1)
      const update = activities.find(a => a.id === updateNote.id)
      assert.strictEqual(update.object?.contentMap?.en, 'Hello, world! (updated)')
    })

    it('correct value for create in inbox', async () => {
      const activities = await getMembers(actor1.inbox, token1)
      const create = activities.find(a => a.id === createNote.id)
      assert.strictEqual(create.object?.contentMap?.en, 'Hello, world! (updated)')
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
      [actor2, token2] = await registerActor(3001)
      const follow = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await delay(100)
      createNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Delete',
        object: createNote.object.id
      })
      await delay(100)
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
      const create = activities.find(a => a.id === createNote.id)
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
      [actor2, token2] = await registerActor(3001)
      const follow = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await delay(100)
      createNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await delay(100)
      like = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor2.id, 'https://www.w3.org/ns/activitystreams#Public'],
        type: 'Like',
        object: createNote.object.id
      })
      await delay(100)
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
      [actor2, token2] = await registerActor(3001)
      const follow = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await delay(100)
      createNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await delay(100)
      announce = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor2.id, 'https://www.w3.org/ns/activitystreams#Public'],
        type: 'Announce',
        object: createNote.object.id
      })
      await delay(100)
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
      [actor2, token2] = await registerActor(3001)
      const follow = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await delay(100)
      createAlbum = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
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
      await delay(100)
      createNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor2.id, 'https://www.w3.org/ns/activitystreams#Public'],
        type: 'Add',
        object: createNote.object.id,
        target: createAlbum.object.id
      })
      await delay(100)
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
      [actor2, token2] = await registerActor(3001)
      const follow = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor2.id,
        type: 'Follow',
        object: actor2.id
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: actor1.id,
        type: 'Accept',
        object: follow.id
      })
      await delay(100)
      createAlbum = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
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
      await delay(100)
      createNote = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor2.id, 'https://www.w3.org/ns/activitystreams#Public'],
        type: 'Add',
        object: createNote.object.id,
        target: createAlbum.object.id
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor2.id, 'https://www.w3.org/ns/activitystreams#Public'],
        type: 'Remove',
        object: createNote.object.id,
        target: createAlbum.object.id
      })
      await delay(100)
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
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      announce = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Announce',
        object: createNote.object.id
      })
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Undo',
        object: announce.id
      })
    })

    it('correct count of shares', async () => {
      const shares = await getObject(createNote.object.shares.id, token1)
      assert.equal(shares.totalItems, 0)
    })

    it('announce not in shares', async () => {
      assert(!await isInStream(createNote.object.shares, announce, token1))
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
      [actor2, token2] = await registerActor(3001)
      const follow = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor1.id],
        type: 'Follow',
        object: actor1.id
      })
      await delay(100)
      await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor2.id],
        type: 'Accept',
        object: follow.id
      })
      await delay(100)
      createNote = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await delay(100)
      like = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public', actor1.id],
        type: 'Like',
        object: createNote.object.id
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public', actor1.id],
        type: 'Undo',
        object: like.id
      })
      await delay(100)
    })

    it('activity is not in object likes stream', async () => {
      assert(!await isInStream(createNote.object.likes, like, token1))
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
      [actor2, token2] = await registerActor(3001)
      const follow = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor1.id],
        type: 'Follow',
        object: actor1.id
      })
      await delay(100)
      await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor2.id],
        type: 'Accept',
        object: follow.id
      })
      await delay(100)
      createNote = await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public'],
        type: 'Create',
        object: {
          type: 'Note',
          contentMap: {
            en: 'Hello, world!'
          }
        }
      })
      await delay(100)
      share = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public', actor1.id],
        type: 'Announce',
        object: createNote.object.id
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public', actor1.id],
        type: 'Undo',
        object: share.id
      })
      await delay(100)
    })

    it('activity is not in object shares stream', async () => {
      assert(!await isInStream(createNote.object.shares, share, token1))
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
      [actor2, token2] = await registerActor(3001)
      follow = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor1.id],
        type: 'Follow',
        object: actor1.id
      })
      await delay(100)
      await doActivity(actor1, token1, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor2.id],
        type: 'Accept',
        object: follow.id
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: ['https://www.w3.org/ns/activitystreams#Public', actor1.id],
        type: 'Undo',
        object: follow.id
      })
      await delay(100)
    })

    it('actor is no longer in followers', async () => {
      assert(!await isInStream(actor1.followers, actor2, token1))
    })

    it('other is no longer in following', async () => {
      assert(!await isInStream(actor2.following, actor1, token2))
    })

    it('actor is not in pending followers', async () => {
      assert(!await isInStream(actor1.pendingFollowers, follow, token1))
    })

    it('other is not in pending following', async () => {
      assert(!await isInStream(actor2.pendingFollowing, follow, token2))
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
      [actor2, token2] = await registerActor(3001)
      follow = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor1.id],
        type: 'Follow',
        object: actor1.id
      })
      await delay(100)
      await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        to: [actor1.id],
        type: 'Undo',
        object: follow.id
      })
      await delay(100)
    })

    it('actor is not in followers', async () => {
      assert(!await isInStream(actor1.followers, actor2, token1))
    })

    it('other is not in following', async () => {
      assert(!await isInStream(actor2.following, actor1, token2))
    })

    it('actor is no longer in pending followers', async () => {
      assert(!await isInStream(actor1.pendingFollowers, follow, token1))
    })

    it('other is no longer in pending following', async () => {
      assert(!await isInStream(actor2.pendingFollowing, follow, token2))
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
      const status = await failActivity(actor1, token1, invalidUpdate('followers'))
      assert(status >= 400 && status <= 499)
    })

    it('fails on setting following', async () => {
      const status = await failActivity(actor1, token1, invalidUpdate('following'))
      assert(status >= 400 && status <= 499)
    })

    it('fails on setting liked', async () => {
      const status = await failActivity(actor1, token1, invalidUpdate('liked'))
      assert(status >= 400 && status <= 499)
    })

    it('fails on setting blocked', async () => {
      const status = await failActivity(actor1, token1, invalidUpdate('blocked'))
      assert(status >= 400 && status <= 499)
    })

    it('fails on setting pendingFollowers', async () => {
      const status = await failActivity(actor1, token1, invalidUpdate('pendingFollowers'))
      assert(status >= 400 && status <= 499)
    })

    it('fails on setting pendingFollowing', async () => {
      const status = await failActivity(actor1, token1, invalidUpdate('pendingFollowing'))
      assert(status >= 400 && status <= 499)
    })

    it('fails on setting outbox', async () => {
      const status = await failActivity(actor1, token1, invalidUpdate('outbox'))
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
        console.log(e)
        assert(false)
      }
      assert.strictEqual(update.object?.inbox?.id, actor1.inbox?.id)
    })

    it('succeeds on setting duplicate followers', async () => {
      const update = await doActivity(actor1, token1, duplicateUpdate('followers'))
      assert.strictEqual(update.object?.followers?.id, actor1.followers?.id)
    })

    it('succeeds on setting duplicate following', async () => {
      const update = await doActivity(actor1, token1, duplicateUpdate('following'))
      assert.strictEqual(update.object?.following?.id, actor1.following?.id)
    })

    it('succeeds on setting duplicate liked', async () => {
      const update = await doActivity(actor1, token1, duplicateUpdate('liked'))
      assert.strictEqual(update.object?.liked?.id, actor1.liked?.id)
    })

    it('succeeds on setting duplicate blocked', async () => {
      const update = await doActivity(actor1, token1, duplicateUpdate('blocked'))
      assert.strictEqual(update.object?.blocked?.id, actor1.blocked?.id)
    })

    it('succeeds on setting duplicate pendingFollowers', async () => {
      const update = await doActivity(actor1, token1, duplicateUpdate('pendingFollowers'))
      assert.strictEqual(update.object?.pendingFollowers?.id, actor1.pendingFollowers?.id)
    })

    it('succeeds on setting duplicate pendingFollowing', async () => {
      const update = await doActivity(actor1, token1, duplicateUpdate('pendingFollowing'))
      assert.strictEqual(update.object?.pendingFollowing?.id, actor1.pendingFollowing?.id)
    })

    it('succeeds on setting duplicate outbox', async () => {
      const update = await doActivity(actor1, token1, duplicateUpdate('outbox'))
      assert.strictEqual(update.object?.outbox?.id, actor1.outbox?.id)
    })
  })

  describe('Login', () => {
    let username = null
    let password = null

    before(async () => {
      [username, , password] = await registerUser()
    })

    it('can get Login page', async () => {
      const res = await fetch('https://localhost:3000/login')
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
      const res = await fetch('https://localhost:3000/login', {
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
      const res2 = await fetch(new URL(location, 'https://localhost:3000/'), {
        headers: { Cookie: cookie }
      })
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
      const reg = await fetch('https://localhost:3000/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: querystring.stringify({
          username,
          password,
          confirmation: password
        })
      })
      const text = await reg.text()
      assert.strictEqual(reg.status, 200, `Bad status code ${reg.status}: ${text}`)
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
    let action = null
    let csrfToken = null
    let accessToken = null
    let refreshToken = null
    let accessToken2 = null
    const clientId = 'test.onepage.pub'
    const redirectUri = 'https://localhost:4000/oauth/callback'
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
        client_id: clientId,
        redirect_uri: redirectUri,
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
      action = body.match(/action="(.+?)"/)[1]
      csrfToken = body.match(/name="csrf_token" value="(.+?)"/)[1]
    })

    it('can get authorization code', async () => {
      const authz = actor.endpoints.oauthAuthorizationEndpoint
      const post = new URL(action, authz)
      const res2 = await fetch(post, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Cookie: cookie
        },
        body: querystring.stringify({
          csrf_token: csrfToken,
          client_id: clientId,
          redirect_uri: redirectUri,
          scope,
          state,
          code_challenge: codeChallenge
        }),
        redirect: 'manual'
      })
      const body2 = await res2.text()
      assert.strictEqual(res2.status, 302, `Bad status code ${res2.status}: ${body2}`)
      assert.ok(res2.headers.get('Location'))
      const location = res2.headers.get('Location')
      assert.strictEqual(location.substring(0, redirectUri.length), redirectUri)
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
          redirect_uri: redirectUri,
          code_verifier: codeVerifier,
          client_id: clientId
        })
      })
      const body3 = await res3.json()
      assert.strictEqual(res3.status, 200, `Bad status code ${res3.status}: ${body3}`)
      assert.strictEqual(res3.headers.get('Content-Type'), 'application/json; charset=utf-8')
      accessToken = body3.access_token
      assert.ok(accessToken)
      assert.strictEqual(body3.token_type, 'Bearer')
      assert.ok(body3.scope)
      assert.ok(body3.expires_in)
      refreshToken = body3.refresh_token
      assert.ok(refreshToken)
    })

    it('can use the access token to read', async () => {
      const res = await fetch(actor.inbox.id, {
        headers: {
          Authorization: `Bearer ${accessToken}`
        }
      })
      const body = await res.json()
      assert.strictEqual(res.status, 200, `Bad status code ${res.status}: ${body}`)
    })

    it('can use the access token to write', async () => {
      const res = await fetch(actor.outbox.id, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/activity+json',
          Authorization: `Bearer ${accessToken}`
        },
        body: JSON.stringify({
          '@context': 'https://www.w3.org/ns/activitystreams',
          type: 'IntransitiveActivity'
        })
      })
      const body = await res.json()
      assert.strictEqual(res.status, 201, `Bad status code ${res.status}: ${body}`)
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
      assert.strictEqual(res.headers.get('Content-Type'), 'application/json; charset=utf-8')
      accessToken2 = body.access_token
      assert.ok(accessToken2)
      assert.strictEqual(body.token_type, 'Bearer')
      assert.ok(body.scope)
      assert.ok(body.expires_in)
    })

    it('can use the refreshed access token to read', async () => {
      const res = await fetch(actor.inbox.id, {
        headers: {
          Authorization: `Bearer ${accessToken2}`
        }
      })
      const body = await res.json()
      assert.strictEqual(res.status, 200, `Bad status code ${res.status}: ${body}`)
    })

    it('can use the refreshed access token to write', async () => {
      const res = await fetch(actor.outbox.id, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/activity+json',
          Authorization: `Bearer ${accessToken2}`
        },
        body: JSON.stringify({
          '@context': 'https://www.w3.org/ns/activitystreams',
          type: 'IntransitiveActivity'
        })
      })
      const body = await res.json()
      assert.strictEqual(res.status, 201, `Bad status code ${res.status}: ${body}`)
    })
  })

  describe('OAuth 2.0 read-only scope', () => {
    let actor = null
    let cookie = null
    let token = null
    let note = null
    before(async () => {
      [actor, , cookie] = await registerActor()
      const [actor2, token2] = await registerActor(3001)
      const activity = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
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
    it('can get access code', async () => {
      token = await getAccessToken(actor, cookie, 'read')
      assert.ok(token)
    })
    it('can use the access token to read local', async () => {
      // This is a private collection so should only be available to the actor
      const pendingFollowers = await getObject(actor.pendingFollowers.id, token)
      assert.strictEqual(pendingFollowers.totalItems, 0)
    })
    it('can use the access token to read remote', async () => {
      const remoteNote = await getObject(note.id, token)
      assert.strictEqual(remoteNote.contentMap?.en, 'Hello, world!')
    })
    it('cannot use the access token to write', async () => {
      const status = await failActivity(actor, token, {
        '@context': 'https://www.w3.org/ns/activitystreams',
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
      const [actor2, token2] = await registerActor(3001)
      const activity = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
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
    it('can use the access token to write', async () => {
      const activity = await doActivity(actor, token, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'IntransitiveActivity'
      })
      assert.ok(activity)
    })
    it('cannot use the access token to read local', async () => {
      // This is a private collection so should only be available to the actor
      const res = await fetch(actor.pendingFollowers.id, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      })
      assert.strictEqual(res.status, 403)
    })
    it('cannot use the access token to read remote', async () => {
      assert(!(await canGetProxy(note.id, actor, token)))
    })
  })

  describe('Cannot use authorization code as access token', { only: true }, () => {
    let actor = null
    let code = null
    let note = null
    before(async () => {
      let cookie = null;
      [actor, , cookie] = await registerActor()
      code = await getAuthCode(actor, cookie)
      const [actor2, token2] = await registerActor(3001)
      const activity = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
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
    it('cannot use the authorization code to read', { only: true }, async () => {
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
    it('cannot use the authorization code to write', { only: true }, async () => {
      const status = await failActivity(actor, code, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'IntransitiveActivity'
      })
      assert.strictEqual(status, 401)
    })
    it('cannot use the authorization code to read through proxy', { only: true }, async () => {
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

  describe('Cannot use refresh token as access token', { only: true }, () => {
    let actor = null
    let refreshToken = null
    let note = null
    before(async () => {
      let cookie = null;
      [actor, , cookie] = await registerActor()
      const [code, codeVerifier] = await getAuthCode(actor, cookie);
      [, refreshToken] = await getTokens(actor, code, codeVerifier)
      const [actor2, token2] = await registerActor(3001)
      const activity = await doActivity(actor2, token2, {
        '@context': 'https://www.w3.org/ns/activitystreams',
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
    it('cannot use the refresh token to read', { only: true }, async () => {
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
    it('cannot use the authorization code to write', { only: true }, async () => {
      const status = await failActivity(actor, refreshToken, {
        '@context': 'https://www.w3.org/ns/activitystreams',
        type: 'IntransitiveActivity'
      })
      assert.strictEqual(status, 401)
    })
    it('cannot use the authorization code to read through proxy', { only: true }, async () => {
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
})
