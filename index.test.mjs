import {describe, before, after, it} from 'node:test';
import {exec} from 'node:child_process';
import assert from 'node:assert';
import querystring from 'node:querystring';

process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

const registerUser = (() => {
    let i = 100;
    return async() => {
        i++;
        const username = `testuser${i}`;
        const password = `testpassword${i}`
        const reg = await fetch('https://localhost:3000/register', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: querystring.stringify({username, password, confirmation: password}),
        })
        const text = await reg.text()
        const token = text.match(/<span class="token">(.*?)<\/span>/)[1]
        return [username, token]
    }
})()

const registerActor = async() => {
    const [username, token] = await registerUser()
    const res = await fetch(`https://localhost:3000/.well-known/webfinger?resource=acct:${username}@localhost:3000`)
    const obj = await res.json()
    const actorId = obj.links[0].href
    const actorRes = await fetch(actorId)
    const actor = await actorRes.json()
    return [actor, token]
}

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
            assert.strictEqual(res.status, 200)
            assert.strictEqual(res.headers.get('Content-Type'), 'text/html; charset=utf-8')
            const body = await res.text()
            assert(body.includes('Registered'))
            assert(body.includes(username))
            assert(body.match('<span class="token">.+?</span>'))
        })
    })

    describe("Webfinger", () => {
        let username = null
        let token = null
        before(async() => {
            [username, token] = await registerUser()
        })
        it("can get information about a user", async () => {
            const res = await fetch(`https://localhost:3000/.well-known/webfinger?resource=acct:${username}@localhost:3000`)
            if (res.status !== 200) {
                body = await res.text()
                console.log(body)
            }
            assert.strictEqual(res.status, 200)
            assert.strictEqual(res.headers.get('Content-Type'), 'application/jrd+json; charset=utf-8')
            const obj = await res.json()
            assert.strictEqual(obj.subject, `acct:${username}@localhost:3000`)
            assert.strictEqual(obj.links[0].rel, 'self')
            assert.strictEqual(obj.links[0].type, 'application/activity+json')
            assert(obj.links[0].href.startsWith('https://localhost:3000/person/'))
        })
    })

    describe("Actor", () => {
        let username = null
        let token = null
        let actorId = null
        before(async () => {
            [username, token] = await registerUser()
            const res = await fetch(`https://localhost:3000/.well-known/webfinger?resource=acct:${username}@localhost:3000`)
            const obj = await res.json()
             actorId = obj.links[0].href
        })
        it("can get actor data", async () => {
            const actorRes = await fetch(actorId)
            const actorBody = await actorRes.text()
            assert.strictEqual(actorRes.status, 200, `Bad status code ${actorRes.status}: ${actorBody}`)
            assert.strictEqual(actorRes.headers.get('Content-Type'), 'application/activity+json; charset=utf-8')
            const actorObj = JSON.parse(actorBody)
            assert.strictEqual(actorObj.id, actorId)
            assert.strictEqual(actorObj.type, 'Person')
            assert.strictEqual(actorObj.name, username)
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
        let token = null
        before(async () => {
            [actor, token] = await registerActor()
        })
        it("can get actor inbox", async () => {
            const res = await fetch(actor.inbox)
            assert.strictEqual(res.status, 200)
            assert.strictEqual(res.headers.get('Content-Type'), 'application/activity+json; charset=utf-8')
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
            assert.strictEqual(res.status, 200)
            assert.strictEqual(res.headers.get('Content-Type'), 'application/activity+json; charset=utf-8')
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
            assert.strictEqual(res.status, 200)
            assert.strictEqual(res.headers.get('Content-Type'), 'application/activity+json; charset=utf-8')
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
            assert.strictEqual(res.status, 200)
            assert.strictEqual(res.headers.get('Content-Type'), 'application/activity+json; charset=utf-8')
            const obj = await res.json()
            assert.strictEqual(obj.id, actor.following)
            assert.strictEqual(obj.type, 'OrderedCollection')
            assert.strictEqual(obj.totalItems, 0)
            assert(obj.name)
            assert(obj.first)
            assert(obj.first.startsWith('https://localhost:3000/orderedcollectionpage/'))
        })
        it("can get actor liked", async () => {
            const res = await fetch(actor.liked)
            assert.strictEqual(res.status, 200)
            assert.strictEqual(res.headers.get('Content-Type'), 'application/activity+json; charset=utf-8')
            const obj = await res.json()
            assert.strictEqual(obj.id, actor.liked)
            assert.strictEqual(obj.type, 'OrderedCollection')
            assert.strictEqual(obj.totalItems, 0)
            assert(obj.name)
            assert(obj.first)
            assert(obj.first.startsWith('https://localhost:3000/orderedcollectionpage/'))
        })
    })
    describe("Post to outbox", () => {
        let actor = null
        let token = null
        before(async () => {
            [actor, token] = await registerActor()
        })
        it("can post an activity to the outbox", async () => {
            const activity = {
                "@context": "https://www.w3.org/ns/activitystreams",
                "type": "IntransitiveActivity",
                "to": "https://www.w3.org/ns/activitystreams#Public"
            }
            const res = await fetch(actor.outbox, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/activity+json; charset=utf-8',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify(activity)
            })
            const body = await res.text()
            assert.strictEqual(res.status, 200, `Bad status code ${res.status}: ${body}`)
            assert.strictEqual(res.headers.get('Content-Type'), 'application/activity+json; charset=utf-8')
            const obj = JSON.parse(body)
            assert(obj.id)
            assert.strictEqual(obj.type, activity.type)
            assert.strictEqual(obj.to, activity.to)
            const inbox = await (await fetch(actor.inbox)).json()
            const inboxPage = await (await fetch(inbox.first)).json()
            const outbox = await (await fetch(actor.outbox)).json()
            const outboxPage = await (await fetch(outbox.first)).json()
            assert.notEqual(-1, inboxPage.orderedItems.indexOf(obj.id))
            assert.notEqual(-1, outboxPage.orderedItems.indexOf(obj.id))
        })
    })
    describe("Follow Activity", () => {
        let actor1 = null
        let token1 = null
        let actor2 = null
        let token2 = null
        let activity = null
        let obj = null
        before(async () => {
            [actor1, token1] = await registerActor();
            [actor2, token2] = await registerActor();
            activity = {
                "@context": "https://www.w3.org/ns/activitystreams",
                "type": "Follow",
                "object": actor2.id,
                "to": ["https://www.w3.org/ns/activitystreams#Public", actor2.id]
            }
            const res = await fetch(actor1.outbox, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/activity+json; charset=utf-8',
                    'Authorization': `Bearer ${token1}`
                },
                body: JSON.stringify(activity)
            })
            const body = await res.text()
            obj = JSON.parse(body)
        })

        it("appears in the actor's inbox", async () => {
            assert(obj.to.every((v, i) => v == activity.to[i]))
            let inbox1 = await (await fetch(actor1.inbox)).json()
            let inboxPage1 = await (await fetch(inbox1.first)).json()
            assert.notEqual(-1, inboxPage1.orderedItems.indexOf(obj.id))
        })

        it("appears in the actor's outbox", async () => {
            const outbox1 = await (await fetch(actor1.outbox)).json()
            const outboxPage1 = await (await fetch(outbox1.first)).json()
            assert.notEqual(-1, outboxPage1.orderedItems.indexOf(obj.id))
        })

        it("appears in the other's inbox", async () => {
           const inbox2 = await (await fetch(actor2.inbox)).json()
            const inboxPage2 = await (await fetch(inbox2.first)).json()
            assert.notEqual(-1, inboxPage2.orderedItems.indexOf(obj.id))
        })

        it("puts the actor in the other's followers", async () => {
            const followers2 = await (await fetch(actor2.followers)).json()
            const followersPage2 = await (await fetch(followers2.first)).json()
            assert.notEqual(-1, followersPage2.orderedItems.indexOf(actor1.id))
        })

        it("puts the other in the actor's following", async() => {

            const following1 = await (await fetch(actor1.following)).json()
            const followingPage1 = await (await fetch(following1.first)).json()
            assert.notEqual(-1, followingPage1.orderedItems.indexOf(actor2.id))
        })

        it("distributes to the actor when the other posts to followers", async() => {
            const activity2 = {
                "@context": "https://www.w3.org/ns/activitystreams",
                "type": "IntransitiveActivity",
                "to": actor2.followers
            }
            const res2 = await fetch(actor2.outbox, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/activity+json; charset=utf-8',
                    'Authorization': `Bearer ${token2}`
                },
                body: JSON.stringify(activity2)
            })
            const body2 = await res2.text()
            assert.strictEqual(res2.status, 200, `Bad status code ${res2.status}: ${body2}`)
            assert.strictEqual(res2.headers.get('Content-Type'), 'application/activity+json; charset=utf-8')
            const obj2 = JSON.parse(body2)
            const inbox1 = await (await fetch(actor1.inbox)).json()
            const inboxPage1 = await (await fetch(inbox1.first)).json()
            assert.notEqual(-1, inboxPage1.orderedItems.indexOf(obj2.id))
        })

        it("distributes to the actor when the other posts to public", async() => {
            const activity2 = {
                "@context": "https://www.w3.org/ns/activitystreams",
                "type": "IntransitiveActivity",
                "to": "https://www.w3.org/ns/activitystreams#Public"
            }
            const res2 = await fetch(actor2.outbox, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/activity+json; charset=utf-8',
                    'Authorization': `Bearer ${token2}`
                },
                body: JSON.stringify(activity2)
            })
            const body2 = await res2.text()
            assert.strictEqual(res2.status, 200, `Bad status code ${res2.status}: ${body2}`)
            assert.strictEqual(res2.headers.get('Content-Type'), 'application/activity+json; charset=utf-8')
            const obj2 = JSON.parse(body2)
            const inbox1 = await (await fetch(actor1.inbox)).json()
            const inboxPage1 = await (await fetch(inbox1.first)).json()
            assert.notEqual(-1, inboxPage1.orderedItems.indexOf(obj2.id))
        })
    })
})
