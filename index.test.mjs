import {describe, before, after, it} from 'node:test';
import {exec} from 'node:child_process';
import assert from 'node:assert';
import querystring from 'node:querystring';
import c from 'config';

process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

describe("Web API interface", () => {

    let child = null

    before(() => {
        return new Promise((resolve, reject) => {
            child = exec('node index.mjs')
            child.on('error', reject)
            child.stdout.on('data', (data) => {
                if (data.toString().includes('Listening')) {
                    resolve()
                }
                console.log(`SERVER: ${data.toString()}`)
            })
            child.stderr.on('data', (data) => {console.log(`SERVER ERROR: ${data.toString()}`)})
        })
    })

    after(() => {
        child.kill()
    })

    describe("Root object", () => {
        it("can get the root object", async () => {
            const res = await fetch('https://localhost:3000/')
            const obj = await res.json()
            assert.strictEqual(obj.type, 'Service')
            assert.strictEqual(obj.name, 'One Page Pub')
            assert.strictEqual(obj.id, 'https://localhost:3000/')
        })
    })

    describe("Registration", () => {

        it("can get a registration form", async () => {
            const res = await fetch('https://localhost:3000/register')
            const body = await res.text()
            assert.strictEqual(res.status, 200)
            assert.strictEqual(res.headers.get('Content-Type'), 'text/html; charset=utf-8')
            assert(body.includes('<form'))
            assert(body.includes('name="username"'))
            assert(body.includes('name="password"'))
            assert(body.includes('name="confirmation"'))
        })

        it("can register a user", async () => {
            const username = 'testuser1'
            const password = 'testpassword1'
            const res = await fetch('https://localhost:3000/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: querystring.stringify({username, password, confirmation: password}),
            })
            const body = await res.text()
            if (res.status !== 200) {
                console.log(body)
            }
            assert.strictEqual(res.status, 200)
            assert.strictEqual(res.headers.get('Content-Type'), 'text/html; charset=utf-8')
            assert(body.includes('Registered'))
            assert(body.includes(username))
        })
    })

    describe("Webfinger", () => {
        before(() => {
            const username = 'testuser2';
            const password = 'testpassword2';
            return fetch('https://localhost:3000/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: querystring.stringify({username, password, confirmation: password}),
            })
        })
        it("can get information about a user", async () => {
            const res = await fetch('https://localhost:3000/.well-known/webfinger?resource=acct:testuser2@localhost:3000')
            if (res.status !== 200) {
                body = await res.text()
                console.log(body)
            }
            assert.strictEqual(res.status, 200)
            assert.strictEqual(res.headers.get('Content-Type'), 'application/jrd+json; charset=utf-8')
            const obj = await res.json()
            assert.strictEqual(obj.subject, 'acct:testuser2@localhost:3000')
            assert.strictEqual(obj.links[0].rel, 'self')
            assert.strictEqual(obj.links[0].type, 'application/activity+json')
            assert(obj.links[0].href.startsWith('https://localhost:3000/person/'))
        })
    })
    describe("Actor", () => {
        before(() => {
            const username = 'testuser3';
            const password = 'testpassword3';
            return fetch('https://localhost:3000/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: querystring.stringify({username, password, confirmation: password}),
            })
        })
        it("can get actor data", async () => {
            const res = await fetch('https://localhost:3000/.well-known/webfinger?resource=acct:testuser3@localhost:3000')
            const obj = await res.json()
            const actorId = obj.links[0].href
            const actorRes = await fetch(actorId)
            const actorObj = await actorRes.json()
            assert.strictEqual(actorObj.id, actorId)
            assert.strictEqual(actorObj.type, 'Person')
            assert.strictEqual(actorObj.name, 'testuser3')
            assert(actorObj.inbox)
            assert(actorObj.inbox.startsWith('https://localhost:3000/orderedcollection/'))
            assert(actorObj.outbox)
            assert(actorObj.outbox.startsWith('https://localhost:3000/orderedcollection/'))
            assert(actorObj.followers)
            assert(actorObj.followers.startsWith('https://localhost:3000/orderedcollection/'))
            assert(actorObj.following)
            assert(actorObj.following.startsWith('https://localhost:3000/orderedcollection/'))
            assert(actorObj.liked)
            assert(actorObj.liked.startsWith('https://localhost:3000/orderedcollection/'))
        })
    })
    describe("Actor streams", () => {
        let actor = null
        before(async () => {
            const username = 'testuser4';
            const password = 'testpassword4';
            await fetch('https://localhost:3000/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: querystring.stringify({username, password, confirmation: password}),
            })
            const res = await fetch('https://localhost:3000/.well-known/webfinger?resource=acct:testuser4@localhost:3000')
            const obj = await res.json()
            const actorId = obj.links[0].href
            const actorRes = await fetch(actorId)
            actor = await actorRes.json()
            return
        })
        it("can get actor inbox", async () => {
            const res = await fetch(actor.inbox)
            const obj = await res.json()
            assert.strictEqual(obj.id, actor.inbox)
            assert.strictEqual(obj.type, 'OrderedCollection')
            assert.strictEqual(obj.totalItems, 0)
            assert(obj.name)
            assert(obj.first)
            assert(obj.first.startsWith('https://localhost:3000/orderedcollectionpage/'))
        })
        it("can get actor outbox", async () => {
            const res = await fetch(actor.outbox)
            const obj = await res.json()
            assert.strictEqual(obj.id, actor.outbox)
            assert.strictEqual(obj.type, 'OrderedCollection')
            assert.strictEqual(obj.totalItems, 0)
            assert(obj.name)
            assert(obj.first)
            assert(obj.first.startsWith('https://localhost:3000/orderedcollectionpage/'))
        })
        it("can get actor followers", async () => {
            const res = await fetch(actor.followers)
            const obj = await res.json()
            assert.strictEqual(obj.id, actor.followers)
            assert.strictEqual(obj.type, 'OrderedCollection')
            assert.strictEqual(obj.totalItems, 0)
            assert(obj.name)
            assert(obj.first)
            assert(obj.first.startsWith('https://localhost:3000/orderedcollectionpage/'))
        })
        it("can get actor following", async () => {
            const res = await fetch(actor.following)
            const obj = await res.json()
            assert.strictEqual(obj.id, actor.following)
            assert.strictEqual(obj.type, 'OrderedCollection')
            assert.strictEqual(obj.totalItems, 0)
            assert(obj.name)
            assert(obj.first)
            assert(obj.first.startsWith('https://localhost:3000/orderedcollectionpage/'))
        })
    })
})
