import express from 'express'
import sqlite3 from 'sqlite3'
import passport from 'passport'
import LocalStrategy from 'passport-local'
import fs from 'fs'
import https from 'https'
import wrap from 'express-async-handler'
import createError from 'http-errors'
import { nanoid } from 'nanoid/async'
import bcrypt from 'bcrypt'
import { expressjwt } from 'express-jwt'
import jwt from 'jsonwebtoken'
import { promisify } from 'util'
import crypto from 'crypto'
import winston from 'winston'

// Configuration

const DATABASE = process.env.OPP_DATABASE || ':memory:'
const HOSTNAME = process.env.OPP_HOSTNAME || 'localhost'
const PORT = process.env.OPP_PORT || 3000
const KEY = process.env.OPP_KEY || 'localhost.key'
const CERT = process.env.OPP_CERT || 'localhost.crt'
const LOG_LEVEL = process.env.OPP_LOG_LEVEL || 'warn'
const KEY_DATA = fs.readFileSync(KEY)
const CERT_DATA = fs.readFileSync(CERT)

// Constants

const AS_CONTEXT = 'https://www.w3.org/ns/activitystreams'
const SEC_CONTEXT = 'https://w3id.org/security'
const BLOCKED_CONTEXT = 'https://purl.archive.org/socialweb/blocked'
const PENDING_CONTEXT = 'https://purl.archive.org/socialweb/pending'
const CONTEXT = [AS_CONTEXT, SEC_CONTEXT, BLOCKED_CONTEXT, PENDING_CONTEXT]

const PUBLIC = 'https://www.w3.org/ns/activitystreams#Public'
const PUBLIC_OBJ = { id: PUBLIC, nameMap: { en: 'Public' }, type: 'Collection' }
const MAX_PAGE_SIZE = 20

// Functions

const sign = promisify(jwt.sign)
const generateKeyPair = promisify(crypto.generateKeyPair)

const isString = value => typeof value === 'string' || value instanceof String

async function toId (value) {
  if (typeof value === 'undefined') {
    return null
  } else if (value == null) {
    return null
  } else {
    const obj = new ActivityObject(value)
    return await obj.id()
  }
}

function makeUrl (relative) {
  if (PORT === 443) {
    return `https://${HOSTNAME}/${relative}`
  } else {
    return `https://${HOSTNAME}:${PORT}/${relative}`
  }
}

function standardEndpoints () {
  return {
    proxyUrl: makeUrl('endpoint/proxyUrl')
  }
}

// Classes

class Database {
  constructor (path) {
    const db = new sqlite3.Database(path)

    db.run('CREATE TABLE IF NOT EXISTS user (username VARCHAR(255) PRIMARY KEY, passwordHash VARCHAR(255), actorId VARCHAR(255), privateKey TEXT)')
    db.run('CREATE TABLE IF NOT EXISTS object (id VARCHAR(255) PRIMARY KEY, owner VARCHAR(255), data TEXT)')
    db.run('CREATE TABLE IF NOT EXISTS addressee (objectId VARCHAR(255), addresseeId VARCHAR(255))')

    this.run = promisify((...params) => {
      logger.silly('run() SQL: ' + params[0], params.slice(1))
      db.run(...params)
    })
    this.get = promisify((...params) => {
      logger.silly('get() SQL: ' + params[0], params.slice(1))
      db.get(...params)
    })
    this.all = promisify((...params) => {
      logger.silly('all() SQL: ' + params[0], params.slice(1))
      db.all(...params)
    })
  }
}

class HTTPSignature {
  constructor (keyId, privateKey = null, method = null, url = null, date = null) {
    if (!privateKey) {
      const sigHeader = keyId
      const parts = Object.fromEntries(sigHeader.split(',').map((clause) => {
        const match = clause.match(/^\s*(\w+)\s*=\s*"(.*?)"\s*$/)
        return [match[1], match[2].replace(/\\"/, '"')]
      }))
      if (!parts.keyId || !parts.headers || !parts.signature || !parts.algorithm) {
        throw new Error('Invalid signature header')
      }
      if (parts.algorithm !== 'rsa-sha256') {
        throw new Error('unsupported algorithm')
      }
      this.keyId = parts.keyId
      this.headers = parts.headers
      this.signature = parts.signature
      this.algorithm = parts.algorithm
    } else {
      this.keyId = keyId
      this.privateKey = privateKey
      this.method = method
      this.url = (isString(url)) ? new URL(url) : url
      this.date = date
      this.signature = this.sign(this.signableData())
      this.header = `keyId="${this.keyId}",headers="(request-target) host date",signature="${this.signature.replace(/"/g, '\\"')}",algorithm="rsa-sha256"`
    }
  }

  signableData () {
    const target = (this.url.search && this.url.search.length)
      ? `${this.url.pathname}?${this.url.search}`
      : `${this.url.pathname}`
    let data = `(request-target): ${this.method.toLowerCase()} ${target}\n`
    data += `host: ${this.url.host}\n`
    data += `date: ${this.date}`
    return data
  }

  sign (data) {
    const signer = crypto.createSign('sha256')
    signer.update(data)
    const signature = signer.sign(this.privateKey).toString('base64')
    signer.end()
    return signature
  }

  async validate (req) {
    const lines = []
    for (const name of this.headers.split(' ')) {
      if (name === '(request-target)') {
        lines.push(`(request-target): ${req.method.toLowerCase()} ${req.originalUrl}`)
      } else {
        const value = req.get(name)
        lines.push(`${name}: ${value}`)
      }
    }
    const data = lines.join('\n')
    const publicKey = await ActivityObject.fromRemote(this.keyId)

    if (!await publicKey.json() || !await publicKey.prop('owner') || !await publicKey.prop('publicKeyPem')) {
      return null
    }

    const verifier = crypto.createVerify('sha256')
    verifier.write(data)
    verifier.end()

    if (verifier.verify(await publicKey.prop('publicKeyPem'), Buffer.from(this.signature, 'base64'))) {
      const ownerId = await publicKey.prop('owner')
      const owner = await ActivityObject.fromRemote(ownerId)
      await owner.cache(ownerId, [PUBLIC])
      await publicKey.cache(ownerId, [PUBLIC])
      return owner
    } else {
      return null
    }
  }

  static async authenticate (req, res, next) {
    const sigHeader = req.headers.signature
    if (sigHeader) {
      const signature = new HTTPSignature(sigHeader)
      const remote = await signature.validate(req)
      if (remote) {
        req.auth = { subject: await remote.id() }
      }
    }
    next()
  }
}

// This delightfully simple queue class is
// from https://dev.to/doctolib/using-promises-as-a-queue-co5

class PromiseQueue {
  last = Promise.resolve(true)
  count = 0

  add (operation, title = null) {
    return new Promise((resolve, reject) => {
      this.last = this.last
        .then(() => {
          return operation
        })
        .then((...args) => {
          resolve(...args)
        })
        .catch((err) => {
          reject(err)
        })
    })
  }
}

class ActivityObject {
  #id
  #json
  #owner
  #addressees
  constructor (data) {
    if (!data) {
      throw new Error('No data provided')
    } else if (isString(data)) {
      this.#id = data
    } else {
      this.#json = data
      this.#id = this.#json.id || this.#json['@id'] || null
    }
  }

  static async makeId (type) {
    return makeUrl(`${type.toLowerCase()}/${await nanoid()}`)
  }

  static async getJSON (id) {
    if (id === PUBLIC) {
      return PUBLIC_OBJ
    }
    const row = await db.get('SELECT data FROM object WHERE id = ?', [id])
    if (!row) {
      return null
    } else {
      return JSON.parse(row.data)
    }
  }

  static async get (id) {
    return new ActivityObject(ActivityObject.getJSON(id))
  }

  static async exists (id) {
    const row = await db.get('SELECT id FROM object WHERE id = ?', [id])
    return !!row
  }

  async json () {
    if (!this.#json) {
      this.#json = await ActivityObject.getJSON(this.#id)
    }
    return this.#json
  }

  async _setJson (json) {
    this.#json = json
  }

  async _hasJson () {
    return !!this.#json
  }

  async id () {
    return this.#id
  }

  async type () {
    return this.prop('type')
  }

  async name (lang = null) {
    const [name, nameMap, summary, summaryMap] = await Promise.all([
      this.prop('name'),
      this.prop('nameMap'),
      this.prop('summary'),
      this.prop('summaryMap')
    ])
    if (nameMap && lang in nameMap) {
      return nameMap[lang]
    } else if (name) {
      return name
    } else if (summaryMap && lang in summaryMap) {
      return summaryMap[lang]
    } else if (summary) {
      return summary
    }
  }

  async prop (name) {
    const json = await this.json()
    if (json) {
      return json[name]
    } else {
      return null
    }
  }

  async expand () {
    const json = await this.expanded()
    this.#json = json
  }

  async isCollection () {
    return ['Collection', 'OrderedCollection'].includes(await this.type())
  }

  async isCollectionPage () {
    return ['CollectionPage', 'OrderedCollectionPage'].includes(await this.type())
  }

  async save (owner, addressees) {
    const data = await this.compressed()
    data.type = data.type || this.defaultType()
    data.id = data.id || await ActivityObject.makeId(data.type)
    data.updated = new Date().toISOString()
    data.published = data.published || data.updated
    // self-ownership
    const ownerId = owner || data.id
    await db.run('INSERT INTO object (id, owner, data) VALUES (?, ?, ?)', [data.id, ownerId, JSON.stringify(data)])
    await Promise.all(addressees.map((addressee) =>
      db.run(
        'INSERT INTO addressee (objectId, addresseeId) VALUES (?, ?)',
        [data.id, addressee]
      )))
    this.#id = data.id
    this.#json = data
  }

  async cache (owner, addressees) {
    const dataId = await this.id()
    const data = await this.json()
    const ownerId = owner || data.id
    const qry = 'INSERT OR REPLACE INTO object (id, owner, data) VALUES (?, ?, ?)'
    await db.run(qry, [dataId, ownerId, JSON.stringify(data)])
    await Promise.all(addressees.map((addressee) =>
      db.run(
        'INSERT OR IGNORE INTO addressee (objectId, addresseeId) VALUES (?, ?)',
        [dataId, addressee]
      )))
  }

  async patch (patch) {
    const merged = { ...await this.json(), ...patch, updated: new Date().toISOString() }
    // null means delete
    for (const prop in patch) {
      if (patch[prop] == null) {
        delete merged[prop]
      }
    }
    await db.run(
      'UPDATE object SET data = ? WHERE id = ?',
      [JSON.stringify(merged), await this.id()]
    )
    this.#json = merged
  }

  async replace (replacement) {
    await db.run(
      'UPDATE object SET data = ? WHERE id = ?',
      [JSON.stringify(replacement), await this.id()]
    )
    this.#json = replacement
  }

  async owner () {
    if (!this.#owner) {
      const row = await db.get('SELECT owner FROM object WHERE id = ?', [await this.id()])
      if (!row) {
        this.#owner = null
      } else {
        this.#owner = new ActivityObject(row.owner)
      }
    }
    return this.#owner
  }

  async addressees () {
    if (!this.#addressees) {
      const id = await this.id()
      const rows = await db.all('SELECT addresseeId FROM addressee WHERE objectId = ?', [id])
      this.#addressees = rows.map((row) => new ActivityObject(row.addresseeId))
    }
    return this.#addressees
  }

  async canRead (subject) {
    const owner = await this.owner()
    const addressees = await this.addressees()
    const addresseeIds = await Promise.all(addressees.map((addressee) => addressee.id()))
    if (subject && await User.isUser(owner)) {
      const blockedProp = await owner.prop('blocked')
      const blocked = new Collection(blockedProp)
      if (await blocked.hasMember(subject)) {
        return false
      }
    }
    // anyone can read if it's public
    if (addresseeIds.includes(PUBLIC)) {
      return true
    }
    // otherwise, unauthenticated can't read
    if (!subject) {
      return false
    }
    // owner can always read
    if (subject === await owner.id()) {
      return true
    }
    // direct addressees can always read
    if (addresseeIds.includes(subject)) {
      return true
    }
    // if they're a member of any addressed collection
    for (const addresseeId of addresseeIds) {
      const obj = new ActivityObject(addresseeId)
      if (await obj.isCollection()) {
        const coll = new Collection(obj.json())
        if (await coll.hasMember(subject)) {
          return true
        }
      }
    }
    // Otherwise, can't read
    return false
  }

  async canWrite (subject) {
    const owner = await this.owner()
    // owner can always write
    if (subject === await owner.id()) {
      return true
    }
    // TODO: if we add a way to grant write access
    // to non-owner, add the check here!
    return false
  }

  async brief () {
    const object = await this.json()
    if (!object) {
      return await this.id()
    }
    let brief = {
      id: await this.id(),
      type: await this.type(),
      icon: await this.prop('icon')
    }
    for (const prop of ['nameMap', 'name', 'summaryMap', 'summary']) {
      if (prop in object) {
        brief[prop] = object[prop]
        break
      }
    }
    switch (object.type) {
      case 'Key':
        brief = {
          ...brief,
          owner: object.owner,
          publicKeyPem: object.publicKeyPem
        }
        break
      case 'Note':
        brief = {
          ...brief,
          content: object.content,
          contentMap: object.contentMap
        }
        break
      case 'OrderedCollection':
      case 'Collection':
        brief = {
          ...brief,
          first: object.first
        }
    }
    return brief
  }

  static #idProps = [
    'actor',
    'alsoKnownAs',
    'attachment',
    'attributedTo',
    'anyOf',
    'audience',
    'blocked',
    'cc',
    'context',
    'current',
    'describes',
    'first',
    'following',
    'followers',
    'generator',
    'href',
    'icon',
    'image',
    'inbox',
    'inReplyTo',
    'instrument',
    'last',
    'liked',
    'likes',
    'location',
    'next',
    'object',
    'oneOf',
    'origin',
    'outbox',
    'partOf',
    'pendingFollowers',
    'pendingFollowing',
    'prev',
    'preview',
    'publicKey',
    'relationship',
    'replies',
    'result',
    'shares',
    'subject',
    'tag',
    'target',
    'to',
    'url'
  ]

  static #arrayProps = [
    'items',
    'orderedItems'
  ]

  async expanded () {
    // force a full read
    const object = await ActivityObject.getJSON(await this.id())
    const toBrief = async (value) => {
      if (value) {
        const obj = new ActivityObject(value)
        return await obj.brief()
      } else {
        return value
      }
    }

    for (const prop of ActivityObject.#idProps) {
      if (prop in object) {
        if (Array.isArray(object[prop])) {
          object[prop] = await Promise.all(object[prop].map(toBrief))
        } else {
          object[prop] = await toBrief(object[prop])
        }
      }
    }

    if (await this.needsExpandedObject()) {
      const activityObject = new ActivityObject(await this.prop('object'))
      object.object = await activityObject.expanded()
    }

    return object
  }

  async compressed () {
    const object = this.json()
    const toIdOrValue = async (value) => {
      const id = await new ActivityObject(value).id()
      if (id) {
        return id
      } else {
        return value
      }
    }

    for (const prop of ActivityObject.#idProps) {
      if (prop in object) {
        if (Array.isArray(object[prop])) {
          object[prop] = await Promise.all(object[prop].map(toIdOrValue))
        } else {
          object[prop] = await toIdOrValue(object[prop])
        }
      }
    }

    for (const prop of ActivityObject.#arrayProps) {
      if (prop in object) {
        if (Array.isArray(object[prop])) {
          object[prop] = await Promise.all(object[prop].map(toIdOrValue))
        } else {
          object[prop] = await toIdOrValue(object[prop])
        }
      }
    }
    return object
  }

  static async fromActivityObject (object) {
    return new ActivityObject(await object.json())
  }

  defaultType () {
    return 'Object'
  }

  static async fromRemote (value) {
    const ao = new ActivityObject(value)
    const obj = await ao.json()
    if (!obj) {
      const id = await ao.id()
      let res = null
      try {
        res = await fetch(id, {
          headers: { Accept: 'application/activity+json, application/ld+json, application/json' }
        })
      } catch (err) {
        console.error(err)
        throw err
      }
      if (res.status !== 200) {
        throw new Error(`Error fetching ${id}: ${res.status}`)
      } else {
        ao.#json = await res.json()
      }
    }
    return ao
  }

  async needsExpandedObject () {
    return ['Create', 'Update', 'Accept', 'Reject', 'Announce'].includes(await this.type())
  }
}

class Activity extends ActivityObject {
  static async fromActivityObject (object) {
    return new Activity(await object.json())
  }

  defaultType () {
    return 'Activity'
  }

  async apply (actor, addressees, ...args) {
    let activity = await this.json()
    const actorObj = new ActivityObject(actor)
    const appliers = {
      Follow: async () => {
        const objectProp = await this.prop('object')
        if (!objectProp) {
          throw new createError.BadRequest('No object followed')
        }
        const other = new ActivityObject(objectProp)
        const otherId = await other.id()
        const following = new Collection(await actorObj.prop('following'))
        if (await following.hasMember(otherId)) {
          throw new createError.BadRequest('Already following')
        }
        const pendingFollowing = new Collection(await actorObj.prop('pendingFollowing'))
        if (await pendingFollowing.find(async (act) =>
          await (new ActivityObject(await act.prop('object'))).id() === otherId)) {
          throw new createError.BadRequest('Already pending following')
        }
        let pendingFollowers = null
        const isUser = await User.isUser(other)
        if (isUser) {
          const actorId = await actorObj.id()
          const followers = new Collection(await other.prop('followers'))
          if (await followers.hasMember(actorId)) {
            throw new createError.BadRequest('Already followed')
          }
          pendingFollowers = new Collection(await other.prop('pendingFollowers'))
          if (await pendingFollowers.find(async (act) =>
            await (new ActivityObject(await act.prop('object'))).id() === actorId)) {
            throw new createError.BadRequest('Already pending follower')
          }
        }
        await pendingFollowing.prepend(this)
        if (isUser) {
          await pendingFollowers.prepend(this)
        }
        return activity
      },
      Accept: async () => {
        const objectProp = await this.prop('object')
        if (!objectProp) {
          throw new createError.BadRequest('No object followed')
        }
        const accepted = new ActivityObject(objectProp)
        switch (await accepted.type()) {
          case 'Follow': {
            const pendingFollowers = new Collection(await actorObj.prop('pendingFollowers'))
            if (!await pendingFollowers.hasMember(await accepted.id())) {
              throw new createError.BadRequest('Not awaiting acceptance for follow')
            }
            const other = new ActivityObject(await accepted.prop('actor'))
            const isUser = await User.isUser(other)
            let pendingFollowing = null
            if (isUser) {
              pendingFollowing = new Collection(await other.prop('pendingFollowing'))
              if (!await pendingFollowing.hasMember(await accepted.id())) {
                throw new createError.BadRequest('Not awaiting acceptance for follow')
              }
            }
            await pendingFollowers.remove(accepted)
            const followers = new Collection(await actorObj.prop('followers'))
            await followers.prepend(other)
            if (isUser) {
              await pendingFollowing.remove(accepted)
              const following = new Collection(await other.prop('following'))
              await following.prepend(actorObj)
            }
          }
        }
        return activity
      },
      Reject: async () => {
        const objectProp = await this.prop('object')
        if (!objectProp) {
          throw new createError.BadRequest('No object followed')
        }
        const rejected = new ActivityObject(objectProp)
        switch (await rejected.type()) {
          case 'Follow': {
            const pendingFollowers = new Collection(await actorObj.prop('pendingFollowers'))
            if (!await pendingFollowers.hasMember(await rejected.id())) {
              throw new createError.BadRequest('Not awaiting acceptance for follow')
            }
            const other = new ActivityObject(await rejected.prop('actor'))
            const isUser = await User.isUser(other)
            let pendingFollowing = null
            if (isUser) {
              pendingFollowing = new Collection(await other.prop('pendingFollowing'))
              if (!await pendingFollowing.hasMember(await rejected.id())) {
                throw new createError.BadRequest('Not awaiting acceptance for follow')
              }
            }
            await pendingFollowers.remove(rejected)
            if (isUser) {
              await pendingFollowing.remove(rejected)
            }
          }
        }
        return activity
      },
      Create: async () => {
        const object = activity.object
        if (!object) {
          throw new createError.BadRequest('No object to create')
        }
        object.attributedTo = actor.id
        object.type = object.type || 'Object'
        const summaryEn = `A(n) ${object.type} by ${actor.name}`
        if (!['name', 'nameMap', 'summary', 'summaryMap'].some(p => p in object)) {
          object.summaryMap = {
            en: summaryEn
          }
        }
        for (const prop of ['likes', 'replies', 'shares']) {
          const value = await Collection.empty(await actorObj.id(), addressees,
            { summaryMap: { en: `${prop} of ${summaryEn}` } })
          object[prop] = await value.id()
        }
        const saved = new ActivityObject(object)
        await saved.save(actor.id, addressees)
        activity.object = await saved.id()
        if (await saved.prop('inReplyTo')) {
          const inReplyToProp = await saved.prop('inReplyTo')
          const parent = new ActivityObject(inReplyToProp)
          const parentOwner = await parent.owner()
          if (parentOwner && await User.isUser(parentOwner)) {
            const replies = new Collection(await parent.prop('replies'))
            await replies.prepend(saved)
          }
        }
        return activity
      },
      Update: async () => {
        if (!activity.object) {
          throw new createError.BadRequest('No object to update')
        }
        if (!activity?.object?.id) {
          throw new createError.BadRequest('No id for object to update')
        }
        const object = new ActivityObject(activity?.object?.id)
        const objectOwner = await object.owner()
        if (!objectOwner || await objectOwner.id() !== actor.id) {
          throw new createError.BadRequest("You can't update an object you don't own")
        }
        await object.patch(activity.object)
        activity.object = await object.json()
        return activity
      },
      Delete: async () => {
        if (!activity.object) {
          throw new createError.BadRequest('No object to delete')
        }
        const object = new ActivityObject(activity.object)
        if (!await object.id()) {
          throw new createError.BadRequest('No id for object to delete')
        }
        const objectOwner = await object.owner()
        if (!objectOwner || await objectOwner.id() !== await toId(actor)) {
          throw new createError.BadRequest("You can't delete an object you don't own")
        }
        const timestamp = new Date().toISOString()
        await object.replace({
          id: await object.id(),
          formerType: await object.type(),
          type: 'Tombstone',
          published: await object.prop('published'),
          updated: timestamp,
          deleted: timestamp,
          summaryMap: {
            en: `A deleted ${await object.type()} by ${actor.name}`
          }
        })
        return activity
      },
      Add: async () => {
        if (!activity.object) {
          throw new createError.BadRequest('No object to add')
        }
        const object = new ActivityObject(activity.object)
        if (!await object.id()) {
          throw new createError.BadRequest('No id for object to add')
        }
        if (!activity.target) {
          throw new createError.BadRequest('No target to add to')
        }
        const target = new Collection(activity.target)
        if (!await target.id()) {
          throw new createError.BadRequest('No id for object to add to')
        }
        if (!await target.isCollection()) {
          throw new createError.BadRequest("Can't add to a non-collection")
        }
        const targetOwner = await target.owner()
        if (!targetOwner || await targetOwner.id() !== actor.id) {
          throw new createError.BadRequest("You can't add to an object you don't own")
        }
        for (const prop of ['inbox', 'outbox', 'followers', 'following', 'liked']) {
          if (await target.id() === await toId(actor[prop])) {
            throw new createError.BadRequest(`Can't add an object directly to your ${prop}`)
          }
        }
        if (await target.hasMember(await object.id())) {
          throw new createError.BadRequest('Already a member')
        }
        await target.prepend(object)
        return activity
      },
      Remove: async () => {
        if (!activity.object) {
          throw new createError.BadRequest('No object to remove')
        }
        const object = new ActivityObject(activity.object)
        if (!await object.id()) {
          throw new createError.BadRequest('No id for object to remove')
        }
        if (!activity.target) {
          throw new createError.BadRequest('No target to remove from')
        }
        const target = new Collection(activity.target)
        if (!await target.id()) {
          throw new createError.BadRequest('No id for object to remove from')
        }
        if (!await target.isCollection()) {
          throw new createError.BadRequest("Can't remove from a non-collection")
        }
        const targetOwner = await target.owner()
        if (!targetOwner || await targetOwner.id() !== actor.id) {
          throw new createError.BadRequest("You can't remove from an object you don't own")
        }
        for (const prop of ['inbox', 'outbox', 'followers', 'following', 'liked']) {
          if (await target.id() === await toId(actor[prop])) {
            throw new createError.BadRequest(`Can't remove an object directly from your ${prop}`)
          }
        }
        if (!await target.hasMember(await object.id())) {
          throw new createError.BadRequest('Not a member')
        }
        await target.remove(object)
        return activity
      },
      Like: async () => {
        if (!activity.object) {
          throw new createError.BadRequest('No object to like')
        }
        const object = new ActivityObject(activity.object)
        if (!await object.canRead(actor.id)) {
          throw new createError.BadRequest("Can't like an object you can't read")
        }
        const liked = new Collection(actor.liked)
        if (await liked.hasMember(await object.id())) {
          throw new createError.BadRequest('Already liked!')
        }
        await liked.prepend(object)
        const objectOwner = await object.owner()
        if (await User.isUser(objectOwner)) {
          let likes = null
          const likesProp = await object.prop('likes')
          if (likesProp) {
            likes = new Collection(likesProp)
          } else {
            likes = await Collection.empty(objectOwner, addressees)
            await object.patch({ likes: await likes.id() })
          }
          likes.prependData(activity)
        }
        return activity
      },
      Block: async () => {
        if (!await this.prop('object')) {
          throw new createError.BadRequest('No object to block')
        }
        const blocked = new Collection(await actorObj.prop('blocked'))
        const other = new ActivityObject(await this.prop('object'))
        if (await blocked.hasMember(await other.id())) {
          throw new createError.BadRequest('Already blocked!')
        }
        await blocked.prepend(other)
        const followers = new Collection(await actorObj.prop('followers'))
        await followers.remove(other)
        const following = new Collection(await actorObj.prop('following'))
        await following.remove(other)
        if (await User.isUser(other)) {
          const otherFollowers = new Collection(await other.prop('followers'))
          await otherFollowers.remove(actorObj)
          const otherFollowing = new Collection(await other.prop('following'))
          await otherFollowing.remove(actorObj)
        }
        return activity
      },
      Announce: async () => {
        if (!await this.prop('object')) {
          throw new createError.BadRequest('Nothing to announce')
        }
        const object = new ActivityObject(await this.prop('object'))
        const owner = await object.owner()
        if (await User.isUser(owner)) {
          const shares = new Collection(await object.prop('shares'))
          await shares.prepend(this)
        }
        return activity
      },
      Undo: async () => {
        if (!await this.prop('object')) {
          throw new createError.BadRequest('Nothing to undo')
        }
        const object = new ActivityObject(await this.prop('object'))
        const owner = await object.owner()
        if (await owner.id() !== await actorObj.id()) {
          throw new createError.BadRequest('Cannot undo an object you do not own')
        }
        switch (await object.type()) {
          case 'Like': {
            if (!await object.prop('object')) {
              throw new createError.BadRequest('Nothing liked')
            }
            const likedObject = new ActivityObject(await object.prop('object'))
            const liked = new Collection(await actorObj.prop('liked'))
            await liked.remove(likedObject)
            const likedObjectOwner = await likedObject.owner()
            if (await User.isUser(likedObjectOwner)) {
              const likes = new Collection(await likedObject.prop('likes'))
              await likes.remove(object)
            }
            break
          }
          case 'Block': {
            if (!await object.prop('object')) {
              throw new createError.BadRequest('Nothing liked')
            }
            const blockedObject = new ActivityObject(await object.prop('object'))
            const blocked = new Collection(await actorObj.prop('blocked'))
            await blocked.remove(blockedObject)
            break
          }
          case 'Follow': {
            if (!await object.prop('object')) {
              throw new createError.BadRequest('Nothing followed')
            }
            const followedObject = new ActivityObject(await object.prop('object'))
            const pendingFollowing = new Collection(await actorObj.prop('pendingFollowing'))
            if (await pendingFollowing.hasMember(await object.id())) {
              await pendingFollowing.remove(object)
            } else {
              const following = new Collection(await actorObj.prop('following'))
              await following.remove(followedObject)
            }
            const followedObjectOwner = await followedObject.owner()
            if (await User.isUser(followedObjectOwner)) {
              const pendingFollowers = new Collection(await followedObjectOwner.prop('pendingFollowers'))
              if (await pendingFollowers.hasMember(await object.id())) {
                await pendingFollowers.remove(object)
              } else {
                const followers = new Collection(await followedObject.prop('followers'))
                await followers.remove(actorObj)
              }
            }
            break
          }
          case 'Announce': {
            if (!await object.prop('object')) {
              throw new createError.BadRequest('Nothing announced')
            }
            const sharedObject = new ActivityObject(await object.prop('object'))
            const sharedObjectOwner = await sharedObject.owner()
            if (await User.isUser(sharedObjectOwner)) {
              await sharedObject.expand()
              const shares = new Collection(await sharedObject.prop('shares'))
              await shares.remove(object)
            }
            break
          }
        }
        return activity
      }
    }

    if (await this.type() in appliers) {
      activity = await appliers[await this.type()]()
      this._setJson(activity)
    }
  }

  async distribute (addressees) {
    const owner = await this.owner()
    const activity = await this.expanded()

    // Expand public, followers, other lists

    const expanded = (await Promise.all(addressees.map(async (addressee) => {
      if (addressee === PUBLIC) {
        const followers = new Collection(await owner.prop('followers'))
        return await followers.members()
      } else {
        const obj = new ActivityObject(addressee)
        if (await obj.isCollection()) {
          const coll = new Collection(addressee)
          const objOwner = await obj.owner()
          if (coll &&
              await objOwner.id() === await owner.id()) {
            return await coll.members()
          }
        }
      }
      return addressee
    }))).filter((v, i, a) => v && a.indexOf(v) === i && v !== owner.id).flat()

    // Deliver to each of the expanded addressees

    const body = JSON.stringify(activity)
    const { privateKey } = await db.get('SELECT privateKey FROM user WHERE actorId = ?', [await owner.id()])
    const keyId = await toId(await owner.prop('publicKey'))

    const sendTo = async (addressee) => {
      let other = new ActivityObject(addressee)
      if (await User.isUser(other)) {
        // Local delivery
        const inbox = new Collection(await other.prop('inbox'))
        await inbox.prependData(activity)
      } else {
        other = await ActivityObject.fromRemote(addressee)
        const inboxProp = await other.prop('inbox')
        if (!inboxProp) {
          return
        }
        const inbox = await toId(inboxProp)
        const date = new Date().toUTCString()
        const signature = new HTTPSignature(keyId, privateKey, 'POST', inbox, date)
        const res = await fetch(inbox, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/activity+json; charset=utf-8',
            Signature: signature.header,
            Date: date
          },
          body
        })
        await res.text()
      }
    }

    for (const addressee of expanded) {
      pq.add(sendTo(addressee))
    }
  }
}

class Collection extends ActivityObject {
  static async fromActivityObject (object) {
    return new Collection(await object.json())
  }

  async hasMember (object) {
    const objectId = await toId(object)
    const collection = await this.json()
    const match = (item) => ((isString(item) && item === objectId) || ((typeof item === 'object') && item.id === objectId))
    switch (collection.type) {
      case 'Collection':
      case 'OrderedCollection':
        if (collection.orderedItems) {
          return collection.orderedItems.some(match)
        } else if (collection.items) {
          return collection.items.some(match)
        } else if (collection.first) {
          return await (new Collection(collection.first)).hasMember(objectId)
        }
        break
      case 'CollectionPage':
      case 'OrderedCollectionPage':
        if (collection.orderedItems) {
          return collection.orderedItems.some(match)
        } else if (collection.items) {
          return collection.items.some(match)
        } else if (collection.next) {
          return await (new Collection(collection.next)).hasMember(objectId)
        }
        break
      default:
        return false
    }
  }

  async prependData (data) {
    return this.prepend(new ActivityObject(data))
  }

  async prepend (object) {
    const collection = await this.expanded()
    const objectId = await object.id()
    if (collection.orderedItems) {
      await this.patch({ totalItems: collection.totalItems + 1, orderedItems: [objectId, ...collection.orderedItems] })
    } else if (collection.items) {
      await this.patch({ totalItems: collection.totalItems + 1, items: [objectId, ...collection.items] })
    } else if (collection.first) {
      const first = await new ActivityObject(collection.first)
      const firstJson = await first.expanded()
      if (firstJson.orderedItems.length < MAX_PAGE_SIZE) {
        await first.patch({ orderedItems: [objectId, ...firstJson.orderedItems] })
        await this.patch({ totalItems: collection.totalItems + 1 })
      } else {
        const owner = await this.owner()
        const addressees = await this.addressees()
        const newFirst = new ActivityObject({ type: 'OrderedCollectionPage', partOf: collection.id, orderedItems: [objectId], next: first.id })
        await newFirst.save(owner, addressees)
        await this.patch({ totalItems: collection.totalItems + 1, first: await newFirst.id() })
        await first.patch({ prev: await newFirst.id() })
      }
    }
  }

  async removeData (data) {
    return this.remove(new ActivityObject(data))
  }

  async remove (object) {
    const collection = await this.expanded()
    const objectId = await object.id()
    if (Array.isArray(collection.orderedItems)) {
      const i = collection.orderedItems.indexOf(objectId)
      if (i !== -1) {
        collection.orderedItems.splice(i, 1)
        await this.patch({
          totalItems: collection.totalItems - 1,
          orderedItems: collection.orderedItems
        })
      }
    } else if (Array.isArray(collection.items)) {
      const i = collection.items.indexOf(objectId)
      if (i !== -1) {
        collection.items.splice(i, 1)
        await this.patch({ totalItems: collection.totalItems - 1, items: collection.items })
      }
    } else {
      let ref = collection.first
      while (ref) {
        const page = new ActivityObject(ref)
        const json = await page.expanded()
        for (const prop of ['items', 'orderedItems']) {
          if (json[prop]) {
            const i = json[prop].indexOf(objectId)
            if (i !== -1) {
              const patch = {}
              json[prop].splice(i, 1)
              patch[prop] = json[prop]
              await page.patch(patch)
              await this.patch({ totalItems: collection.totalItems - 1 })
              return
            }
          }
        }
        ref = json.next
      }
    }
    return collection
  }

  async members () {
    const obj = await this.json()
    let cur = obj.items || obj.orderedItems || []
    let ref = obj.first
    while (ref) {
      const page = new ActivityObject(ref)
      if (!await page.isCollectionPage()) {
        break
      }
      const pageJson = await page.json()
      cur = cur.concat(pageJson.items || pageJson.orderedItems || [])
      ref = pageJson.next
    }
    return cur
  }

  static async empty (owner, addressees, props = {}, pageProps = {}) {
    const id = await ActivityObject.makeId('OrderedCollection')
    const page = new ActivityObject({
      type: 'OrderedCollectionPage',
      orderedItems: [],
      partOf: id,
      ...pageProps
    })
    await page.save(owner, addressees)
    const coll = new ActivityObject({
      id,
      type: 'OrderedCollection',
      totalItems: 0,
      first: await page.id(),
      last: await page.id(),
      ...props
    })
    await coll.save(owner, addressees)
    return coll
  }

  async find (test) {
    let ref = this.prop('first')
    while (ref) {
      const page = new ActivityObject(ref)
      if (!await page.isCollectionPage()) {
        break
      }
      const items = (await page.prop('items') || await page.prop('orderedItems') || [])
      for (const item of items) {
        const itemObj = new ActivityObject(item)
        const result = await test(itemObj)
        if (result) {
          return result
        }
      }
      ref = await page.prop('next')
    }
    return false
  }

  defaultType () {
    return 'OrderedCollection'
  }
}

class RemoteActivity extends Activity {
  async save (owner, addressees) {
    const dataId = await this.id()
    const ownerId = await owner.id() || dataId
    await db.run(
      'INSERT INTO object (id, owner, data) VALUES (?, ?, ?)',
      [await dataId, ownerId, JSON.stringify(await this.json())]
    )
    await Promise.all(addressees.map((addressee) =>
      db.run(
        'INSERT INTO addressee (objectId, addresseeId) VALUES (?, ?)',
        [dataId, addressee]
      )))
  }

  async apply (remote, addressees, ...args) {
    const owner = args[0]
    const ownerObj = new ActivityObject(owner)
    const remoteObj = new ActivityObject(remote)
    const activity = await this.json()
    const remoteAppliers = {
      Follow: async () => {
        const object = new ActivityObject(await this.prop('object'))
        if (await object.id() === await ownerObj.id()) {
          const followers = new Collection(await ownerObj.prop('followers'))
          if (await followers.hasMember(remote)) {
            throw new Error('Already a follower')
          }
          const pendingFollowers = new Collection(await ownerObj.prop('pendingFollowers'))
          if (await pendingFollowers.hasMember(await this.id())) {
            throw new Error('Already pending')
          }
          await pendingFollowers.prepend(this)
        }
      },
      Create: async () => {
        if (await this.prop('object')) {
          const ao = new ActivityObject(await this.prop('object'))
          const owner = await ao.owner()
          if (owner && await owner.id() !== await remoteObj.id()) {
            throw new Error('Cannot create something you do not own!')
          }
          await ao.cache(await remoteObj.id(), addressees)
          if (await ao.prop('inReplyTo')) {
            const inReplyTo = new ActivityObject(await ao.prop('inReplyTo'))
            await inReplyTo.expand()
            const inReplyToOwner = await inReplyTo.owner()
            if (inReplyToOwner && await inReplyToOwner.id() === await ownerObj.id()) {
              if (!await inReplyTo.canRead(remote)) {
                throw new Error('Cannot reply to something you cannot read!')
              }
              const replies = new Collection(await inReplyTo.prop('replies'))
              if (!await replies.hasMember(ao)) {
                await replies.prepend(ao)
              }
            }
          }
        }
      },
      Update: async () => {
        if (await this.prop('object')) {
          const ao = new ActivityObject(await this.prop('object'))
          const aoOwner = await ao.owner()
          if (aoOwner && await aoOwner.id() !== await remoteObj.id()) {
            throw new Error('Cannot update something you do not own!')
          }
          await ao.cache(remote, addressees)
          if (await ao.prop('inReplyTo')) {
            const inReplyTo = new ActivityObject(await ao.prop('inReplyTo'))
            await inReplyTo.expand()
            const inReplyToOwner = await inReplyTo.owner()
            if (inReplyToOwner && await inReplyToOwner.id() === await ownerObj.id()) {
              if (!await inReplyTo.canRead(remote)) {
                throw new Error('Cannot reply to something you cannot read!')
              }
              const replies = new Collection(await inReplyTo.prop('replies'))
              if (!await replies.hasMember(ao)) {
                await replies.prepend(ao)
              }
            }
          }
        }
      },
      Delete: async () => {
        if (await this.prop('object')) {
          const ao = new ActivityObject(await this.prop('object'))
          const aoOwner = await ao.owner()
          if (aoOwner && await aoOwner.id() !== await remoteObj.id()) {
            throw new Error('Cannot delete something you do not own!')
          }
          await ao.cache(remote, addressees)
        }
      },
      Like: async () => {
        if (await this.prop('object')) {
          const ao = new ActivityObject(await this.prop('object'))
          const aoOwner = await ao.owner()
          if (await User.isUser(aoOwner)) {
            if (!await ao.canRead(await remoteObj.id())) {
              throw new Error('Cannot like something you cannot read!')
            }
            await ao.expand()
            const likes = new Collection(await ao.prop('likes'))
            if (!await likes.hasMember(this)) {
              await likes.prepend(this)
            }
          }
        }
      },
      Announce: async () => {
        if (await this.prop('object')) {
          const ao = new ActivityObject(await this.prop('object'))
          const aoOwner = await ao.owner()
          if (await User.isUser(aoOwner)) {
            if (!await ao.canRead(await remoteObj.id())) {
              throw new Error('Cannot share something you cannot read!')
            }
            await ao.expand()
            const shares = new Collection(await ao.prop('shares'))
            if (!await shares.hasMember(this)) {
              await shares.prepend(this)
            }
          }
        }
      },
      Add: async () => {
        if (await this.prop('object')) {
          const ao = new ActivityObject(await this.prop('object'))
          const aoOwner = await ao.owner()
          if (await User.isUser(aoOwner)) {
            if (!await ao.canRead(await remoteObj.id())) {
              throw new Error('Cannot add something you cannot read!')
            }
          }
          if (await this.prop('target')) {
            const target = new ActivityObject(await this.prop('target'))
            const targetOwner = await target.owner()
            if (await User.isUser(targetOwner)) {
              if (!await target.canRead(await remoteObj.id())) {
                throw new Error('Cannot add to something you cannot read!')
              }
              if (!await target.canWrite(await remoteObj.id())) {
                throw new Error('Cannot add to something you do not own!')
              }
            }
          }
        }
      },
      Remove: async () => {
        if (await this.prop('object')) {
          const ao = new ActivityObject(await this.prop('object'))
          const aoOwner = await ao.owner()
          if (await User.isUser(aoOwner)) {
            if (!await ao.canRead(await remoteObj.id())) {
              throw new Error('Cannot add something you cannot read!')
            }
          }
          const targetProp = await this.prop('target') || await this.prop('origin')
          if (targetProp) {
            const target = new ActivityObject(targetProp)
            const targetOwner = await target.owner()
            if (await User.isUser(targetOwner)) {
              if (!await target.canRead(await remoteObj.id())) {
                throw new Error('Cannot remove from you cannot read!')
              }
              if (!await target.canWrite(await remoteObj.id())) {
                throw new Error('Cannot remove from something you do not own!')
              }
            }
          }
        }
      },
      Accept: async () => {
        const objectProp = await this.prop('object')
        if (!objectProp) {
          throw new Error('Nothing accepted!')
        }
        const accepted = new ActivityObject(await this.prop('object'))
        switch (await accepted.type()) {
          case 'Follow': {
            const actorProp = await accepted.prop('actor')
            if (!actorProp) {
              throw new Error('No actor!')
            }
            const actor = new ActivityObject(actorProp)
            const objectProp = await accepted.prop('object')
            if (!objectProp) {
              throw new Error('No object!')
            }
            const object = new ActivityObject(objectProp)
            if (await actor.id() === await ownerObj.id() &&
              await object.id() === await remoteObj.id()) {
              const pendingFollowing = new Collection(await ownerObj.prop('pendingFollowing'))
              if (!await pendingFollowing.hasMember(await accepted.id())) {
                throw new Error('Not pending!')
              }
              const following = new Collection(await ownerObj.prop('following'))
              if (await following.hasMember(await object.id())) {
                throw new Error('Already following!')
              }
              await pendingFollowing.remove(accepted)
              await following.prepend(object)
            }
            break
          }
        }
      },
      Reject: async () => {
        const objectProp = await this.prop('object')
        if (!objectProp) {
          throw new Error('Nothing rejected!')
        }
        const rejected = new ActivityObject(await this.prop('object'))
        switch (await rejected.type()) {
          case 'Follow': {
            const actorProp = await rejected.prop('actor')
            if (!actorProp) {
              throw new Error('No actor!')
            }
            const actor = new ActivityObject(actorProp)
            const objectProp = await rejected.prop('object')
            if (!objectProp) {
              throw new Error('No object!')
            }
            const object = new ActivityObject(objectProp)
            if (await actor.id() === await ownerObj.id() &&
              await object.id() === await remoteObj.id()) {
              const pendingFollowing = new Collection(await ownerObj.prop('pendingFollowing'))
              if (!await pendingFollowing.hasMember(await rejected.id())) {
                throw new Error('Not pending!')
              }
              const following = new Collection(await ownerObj.prop('following'))
              if (await following.hasMember(await object.id())) {
                throw new Error('Already following!')
              }
              await pendingFollowing.remove(rejected)
            }
            break
          }
        }
      },
      Undo: async () => {
        const objectProp = await this.prop('object')
        if (!objectProp) {
          throw new Error('Nothing undone!')
        }
        const undone = new ActivityObject(await this.prop('object'))
        await undone.expand()
        switch (await undone.type()) {
          case 'Like': {
            // Make sure it's expanded
            const actorProp = await undone.prop('actor')
            if (!actorProp) {
              throw new Error('No actor!')
            }
            const likeActor = new ActivityObject(actorProp)
            if (await remoteObj.id() !== await likeActor.id()) {
              throw new Error('Not your like!')
            }
            const objectProp = await undone.prop('object')
            const object = new ActivityObject(objectProp)
            if (!await object.canRead(await remoteObj.id())) {
              throw new Error('Cannot unlike something you cannot read!')
            }
            const objectOwner = await object.owner()
            if (await User.isUser(objectOwner)) {
              await object.expand()
              const likes = new Collection(await object.prop('likes'))
              await likes.remove(undone)
            }
          }
        }
      }
    }

    if (activity.type in remoteAppliers) {
      await remoteAppliers[activity.type]()
    }
  }
}

class User {
  constructor (username, password = null) {
    this.username = username
    this.password = password
  }

  async save () {
    this.actorId = await ActivityObject.makeId('Person')
    const data = { name: this.username, id: this.actorId, type: 'Person', preferredUsername: this.username }
    const props = ['inbox', 'outbox', 'followers', 'following', 'liked']
    for (const prop of props) {
      const coll = await Collection.empty(this.actorId, [PUBLIC], { nameMap: { en: `${this.username}'s ${prop}` } })
      data[prop] = await coll.id()
    }
    const privProps = ['blocked', 'pendingFollowers', 'pendingFollowing']
    for (const prop of privProps) {
      const coll = await Collection.empty(this.actorId, [], { nameMap: { en: `${this.username}'s ${prop}` } })
      data[prop] = await coll.id()
    }
    const { publicKey, privateKey } = await generateKeyPair(
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
    const pkey = new ActivityObject({ type: 'Key', owner: this.actorId, publicKeyPem: publicKey })
    await pkey.save(this.actorId, [PUBLIC])
    data.publicKey = await pkey.brief()
    const person = new ActivityObject(data)
    await person.save(this.actorId, [PUBLIC])
    const passwordHash = await bcrypt.hash(this.password, 10)
    await db.run('INSERT INTO user (username, passwordHash, actorId, privateKey) VALUES (?, ?, ?, ?)', [this.username, passwordHash, this.actorId, privateKey])
  }

  static async isUser (object) {
    const id = await object.id()
    const row = await db.get('SELECT actorId FROM user WHERE actorId = ?', [id])
    return !!row
  }

  static async usernameExists (username) {
    const row = await db.get('SELECT username FROM user WHERE username = ?', [username])
    return !!row
  }

  static async fromActorId (actorId) {
    const row = await db.get('SELECT * FROM user WHERE actorId = ?', [actorId])
    if (!row) {
      return null
    } else {
      const user = new User(row.username)
      user.actorId = row.actorId
      user.privateKey = row.privateKey
      return user
    }
  }

  async getActor (username) {
    const actor = new ActivityObject(this.actorId)
    return actor
  }
}

// Server

const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: winston.format.printf((info) => {
    return `${(new Date()).toISOString()} ${info.level}: ${info.message}`
  }),
  transports: [
    new winston.transports.Console()
  ]
})

// verbose output

sqlite3.verbose()

// Initialize SQLite
const db = new Database(DATABASE)

// Initialize PromiseQueue

const pq = new PromiseQueue()
pq.add(async () => {})

// Initialize Express
const app = express()

app.use((req, res, next) => {
  const oldEnd = res.end
  res.end = function (...args) {
    logger.info(`${res.statusCode} ${req.method} ${req.url}`)
    oldEnd.apply(this, args)
  }
  next()
})

app.use(passport.initialize()) // Initialize Passport
app.use(express.json({ type: ['application/json', 'application/activity+json'] })) // for parsing application/json
app.use(express.urlencoded({ extended: true })) // for HTML forms

// Local Strategy for login/logout
passport.use(new LocalStrategy(
  function (username, password, done) {

  }
))

app.get('/', wrap(async (req, res) => {
  const url = req.protocol + '://' + req.get('host') + req.originalUrl
  res.set('Content-Type', 'application/activity+json')
  res.json({
    '@context': CONTEXT,
    id: url,
    name: process.OPP_NAME || 'One Page Pub',
    type: 'Service'
  })
}))

app.get('/register', wrap(async (req, res) => {
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

app.post('/register', wrap(async (req, res) => {
  if (req.get('Content-Type') !== 'application/x-www-form-urlencoded') {
    throw new createError.BadRequest('Invalid Content-Type')
  }
  if (!req.body.username) {
    throw new createError.BadRequest('Username is required')
  }
  if (!req.body.password) {
    throw new createError.BadRequest('Password is required')
  }
  if (req.body.password !== req.body.confirmation) {
    throw new createError.BadRequest('Passwords do not match')
  }
  const username = req.body.username

  if (await User.usernameExists(username)) {
    throw new createError.BadRequest('Username already exists')
  }

  const password = req.body.password
  const user = new User(username, password)
  await user.save()
  const token = await sign(
    {
      subject: user.actorId,
      issuer: req.protocol + '://' + req.get('host') + '/'
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
    <p>Registered <a class="actor" href="${user.actorId}">${username}</a></p>
    <p>Personal access token is <span class="token">${token}</span>
    </body>
    </html>`)
}))

app.get('/.well-known/webfinger', wrap(async (req, res) => {
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
  const user = await db.get('SELECT username, actorId FROM user WHERE username = ?', [username])
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
    subject: resource,
    links: [
      {
        rel: 'self',
        type: 'application/activity+json',
        href: user.actorId
      }
    ]
  })
}))

app.post('/endpoint/proxyUrl',
  expressjwt({ secret: KEY_DATA, credentialsRequired: true, algorithms: ['RS256'] }),
  wrap(async (req, res) => {
    const id = req.body.id
    if (!id) {
      throw new createError.BadRequest('Missing id')
    }
    const user = await User.fromActorId(req.auth?.subject)
    if (!user) {
      throw new createError.InternalServerError('Invalid user')
    }
    const actor = await user.getActor()
    const publicKey = new ActivityObject(await actor.prop('publicKey'))
    const date = new Date().toUTCString()
    const signature = new HTTPSignature(await publicKey.id(), user.privateKey, 'GET', id, date)
    const fetchRes = await fetch(id, {
      headers: {
        Accept: 'application/activity+json;q=1,application/ld+json;q=0.5,application/json;q=0.1',
        Signature: signature.header,
        Date: date
      }
    })
    if (![200, 410].includes(fetchRes.status)) {
      throw new createError.InternalServerError('Error fetching object')
    }
    const fetchJson = await fetchRes.json()
    if (fetchRes.status === 410 && fetchJson.type !== 'Tombstone') {
      throw new createError.InternalServerError('Error fetching object')
    }
    res.status(fetchRes.status)
    res.set('Content-Type', 'application/activity+json')
    res.json(fetchJson)
  }))

app.get('/:type/:id',
  expressjwt({ secret: KEY_DATA, credentialsRequired: false, algorithms: ['RS256'] }),
  HTTPSignature.authenticate,
  wrap(async (req, res) => {
    const full = req.protocol + '://' + req.get('host') + req.originalUrl
    const type = req.params.type
    if (!(await ActivityObject.exists(full))) {
      throw new createError.NotFound('Object not found')
    }
    const obj = new ActivityObject(full)
    if (!(await obj.canRead(req.auth?.subject))) {
      if (req.auth?.subject) {
        throw new createError.Forbidden('Not authorized to read this object')
      } else {
        throw new createError.Unauthorized(`You must provide credentials to read ${full}`)
      }
    }
    const objType = await obj.type()
    if (objType.toLowerCase() !== type && objType !== 'Tombstone') {
      throw new createError.InternalServerError('Invalid object type')
    }
    const output = await obj.expanded()
    for (const name of ['items', 'orderedItems']) {
      if (name in output && Array.isArray(output[name])) {
        const len = output[name].length
        for (let i = len - 1; i >= 0; i--) {
          const item = new ActivityObject(output[name][i])
          if (!(await item.canRead(req.auth?.subject))) {
            output[name].splice(i, 1)
          } else {
            output[name][i] = await item.expanded()
          }
        }
      }
    }
    if (await User.isUser(obj)) {
      output.endpoints = standardEndpoints()
    }
    if (output.type === 'Tombstone') {
      res.status(410)
    }
    output['@context'] = output['@context'] || CONTEXT
    res.set('Content-Type', 'application/activity+json')
    res.json(output)
  }))

app.post('/:type/:id',
  expressjwt({ secret: KEY_DATA, credentialsRequired: false, algorithms: ['RS256'] }),
  HTTPSignature.authenticate,
  wrap(async (req, res) => {
    const full = req.protocol + '://' + req.get('host') + req.originalUrl
    const obj = new ActivityObject(full)
    if (!obj) {
      throw new createError.NotFound('Object not found')
    }
    const owner = await obj.owner()
    if (!await obj.json()) {
      throw new createError.InternalServerError('Invalid object')
    }
    if (!owner) {
      throw new createError.InternalServerError('No owner found for object')
    }
    if (full === await owner.prop('outbox')) {
      if (req.auth?.subject !== await owner.id()) {
        throw new createError.Forbidden('You cannot post to this outbox')
      }
      const ownerId = await owner.id()
      const ownerJson = await owner.json()
      const outbox = await Collection.fromActivityObject(obj)
      const data = req.body
      const addressees = await Promise.all(['to', 'cc', 'bto', 'bcc']
        .map((prop) => data[prop])
        .filter((a) => a)
        .flat()
        .map(toId))
      data.id = await ActivityObject.makeId(data.type || 'Activity')
      data.actor = ownerId
      const activity = new Activity(data)
      await activity.apply(ownerJson, addressees)
      await activity.save(ownerId, addressees)
      await outbox.prepend(activity)
      const inbox = new Collection(await owner.prop('inbox'))
      await inbox.prepend(activity)
      pq.add(activity.distribute(addressees))
      const output = await activity.expanded()
      output['@context'] = output['@context'] || CONTEXT
      res.status(200)
      res.set('Content-Type', 'application/activity+json')
      res.json(output)
    } else if (full === await owner.prop('inbox')) { // remote delivery
      if (!req.auth?.subject) {
        throw new createError.Unauthorized('Invalid HTTP signature')
      }
      const remote = new ActivityObject(req.auth.subject)
      if (await User.isUser(remote)) {
        throw new createError.Forbidden('Remote delivery only')
      }
      const addressees = await Promise.all(['to', 'cc', 'bto', 'bcc']
        .map((prop) => req.body[prop])
        .filter((a) => a)
        .flat()
        .map(toId))
      // always include the recipient
      addressees.push(await owner.id())
      const activity = new RemoteActivity(req.body)
      await activity.apply(await remote.json(), addressees, await owner.json())
      await activity.save(remote, addressees)
      const inbox = new Collection(await owner.prop('inbox'))
      await inbox.prepend(activity)
      res.status(202)
      res.set('Content-Type', 'application/activity+json')
      res.json(req.body)
    } else {
      throw new createError.MethodNotAllowed('You cannot POST to this object')
    }
  }))

app.use((err, req, res, next) => {
  if (createError.isHttpError(err)) {
    if (err.statusCode > 500) {
      console.error(err)
    }
    res.status(err.statusCode)
    if (res.expose) {
      res.json({ message: err.message })
    } else {
      res.json({ message: err.message })
    }
  } else {
    console.error(err)
    res.status(500)
    res.json({ message: err.message })
  }
})

process.on('unhandledRejection', (err) => {
  console.log('Unhandled rejection')
  console.error(err)
})

process.on('uncaughtException', (err) => {
  console.log('Uncaught exception')
  console.error(err)
})

process.on('exit', (code) => {
  console.log(`About to exit with code: ${code}`)
})

// Start server with SSL
https.createServer({
  key: KEY_DATA,
  cert: CERT_DATA
}, app)
  .listen(PORT, HOSTNAME, () => {
    console.log(`Listening on ${HOSTNAME}:${PORT}`)
  })
