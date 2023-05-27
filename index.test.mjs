import {describe, before, after, it} from 'node:test';
import {exec} from 'node:child_process';
import https from 'node:https';
import assert from 'node:assert';

process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

describe("The root object", () => {
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
    it("can get the root object", async () => {
        const res = await fetch('https://localhost:3000/')
        const obj = await res.json()
        assert.strictEqual(obj.type, 'Service')
    })
})