import {describe, before, after, it} from 'node:test';
import {exec} from 'node:child_process';
import assert from 'node:assert';
import querystring from 'node:querystring';

process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

describe("Web API interface", () => {

    let child = null

    before(() => {
        return new Promise((resolve, reject) => {
            console.log('Starting server')
            child = exec('node index.mjs')
            child.on('error', reject)
            child.stdout.on('data', resolve)
        })
    })

    after(() => {
        console.log('ending server')
        child.kill()
        console.log('server ended')
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
            assert.strictEqual(res.status, 200)
            assert.strictEqual(res.headers.get('Content-Type'), 'text/html; charset=utf-8')
            assert(body.includes('Registered'))
            assert(body.includes(username))
        })
    })
})