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

// Constants

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
const PUBLIC_OBJ = {id: PUBLIC, nameMap: {"en": "Public"}, type: "Collection"}
const MAX_PAGE_SIZE = 20

// Classes

class Database {
    constructor(path) {
        let db = new sqlite3.Database(path);

        db.run('CREATE TABLE IF NOT EXISTS user (username VARCHAR(255) PRIMARY KEY, passwordHash VARCHAR(255), actorId VARCHAR(255), privateKey TEXT)');
        db.run('CREATE TABLE IF NOT EXISTS object (id VARCHAR(255) PRIMARY KEY, owner VARCHAR(255), data TEXT)');
        db.run('CREATE TABLE IF NOT EXISTS addressee (objectId VARCHAR(255), addresseeId VARCHAR(255))')

        this.run = promisify((...params) => { db.run(...params) })
        this.get = promisify((...params) => { db.get(...params) })
        this.all = promisify((...params) => { db.all(...params) })
    }
}

class HTTPSignature {
  constructor(keyId, privateKey=null, method=null, url=null, date=null) {
    if (!privateKey) {
      const sigHeader = keyId;
      const parts = Object.fromEntries(sigHeader.split(',').map((clause) => {
        let match = clause.match(/^\s*(\w+)\s*=\s*"(.*?)"\s*$/)
        return [match[1], match[2].replace(/\\"/, '"')]
      }))
      if (!parts.keyId || !parts.headers || !parts.signature || !parts.algorithm) {
        throw new Error('Invalid signature header')
      }
      if (parts.algorithm != 'rsa-sha256') {
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
      this.url = (isString(url)) ? new URL(url) : url;
      this.date = date
      this.signature = this.sign(this.signableData())
      this.header = `keyId="${this.keyId}",headers="(request-target) host date",signature="${this.signature.replace(/"/g, '\\"')}",algorithm="rsa-sha256"`;
    }
  }

  signableData() {
    const target = (this.url.search && this.url.search.length) ?
    `${this.url.pathname}?${this.url.search}` :
    `${this.url.pathname}`
    let data = `(request-target): ${this.method.toLowerCase()} ${target}\n`
    data += `host: ${this.url.host}\n`
    data += `date: ${this.date}`
    return data
  }

  sign(data) {
    const signer = crypto.createSign('sha256');
    signer.update(data);
    const signature = signer.sign(this.privateKey).toString('base64');
    signer.end();
    return signature;
  }

  async validate(req) {

    let lines = []
    for (let name of this.headers.split(' ')) {
      if (name == '(request-target)') {
        lines.push(`(request-target): ${req.method.toLowerCase()} ${req.originalUrl}`)
      } else {
        let value = req.get(name)
        lines.push(`${name}: ${value}`)
      }
    }
    let data = lines.join('\n')

    const publicKey = await getRemoteObject(this.keyId)
    if (!publicKey || !publicKey.owner || !publicKey.publicKeyPem) {
      return null
    }
    const verifier = crypto.createVerify('sha256');
    verifier.write(data);
    verifier.end();
    if (verifier.verify(publicKey.publicKeyPem, Buffer.from(this.signature, 'base64'))) {
      return ActivityObject.fromRemote(publicKey.owner)
    } else {
      return null
    }
  }
}

class ActivityObject {
  #id;
  #json;
  #owner;
  #addressees;
  constructor(data) {
    if (!data) {
      throw new Error('No data provided');
    } else if (isString(data)) {
      this.#id = data;
    } else {
      this.#json = data;
      this.#id = this.#json.id || this.#json['@id'] || null
    }
  }
  static async makeId(type) {
    if (PORT === 443) {
      return `https://${HOSTNAME}/${type.toLowerCase()}/${await nanoid()}`;
    } else {
      return `https://${HOSTNAME}:${PORT}/${type.toLowerCase()}/${await nanoid()}`;
    }
  }
  static async getJSON(id) {
    if (id == PUBLIC) {
      return PUBLIC_OBJ
    }
    const row = await db.get(`SELECT data FROM object WHERE id = ?`, [id])
    if (!row) {
      return null
    } else {
      return JSON.parse(row.data)
    }
  }
  static async get(id) {
    return new ActivityObject(ActivityObject.getJSON(id))
  }

  static async exists(id) {
    const row = await db.get(`SELECT id FROM object WHERE id = ?`, [id])
    return !!row
  }

  async json() {
    if (!this.#json) {
      this.#json = await ActivityObject.getJSON(this.#id)
    }
    return this.#json;
  }

  async _setJson(json) {
    this.#json = json;
  }

  async _hasJson() {
    return !!this.#json;
  }

  async id() {
    return this.#id
  }

  async type() {
    return this.prop('type')
  }

  async prop(name) {
    const json = await this.json()
    if (json) {
      return json[name]
    } else {
      return null
    }
  }

  async isCollection() {
    return ['Collection', 'OrderedCollection'].includes(await this.type())
  }

  async isCollectionPage() {
    return ['CollectionPage', 'OrderedCollectionPage'].includes(await this.type())
  }

  async save(owner, addressees) {
    const data = await this.compressed()
    data.type = data.type ||  this.defaultType()
    data.id = data.id || await ActivityObject.makeId(data.type)
    data.updated = new Date().toISOString();
    data.published = data.published || data.updated;
    // self-ownership
    const ownerId = owner || data.id
    await db.run('INSERT INTO object (id, owner, data) VALUES (?, ?, ?)', [data.id, ownerId, JSON.stringify(data)]);
    await Promise.all(addressees.map((addressee) =>
      db.run(
        'INSERT INTO addressee (objectId, addresseeId) VALUES (?, ?)',
        [data.id, addressee]
      )))
    this.#id = data.id
    this.#json = data
  }

  async patch(patch) {
    const merged = {...await this.json(), ...patch, updated: new Date().toISOString()}
    // null means delete
    for (let prop in patch) {
      if (patch[prop] == null) {
        delete merged[prop]
      }
    }
    await db.run(
      `UPDATE object SET data = ? WHERE id = ?`,
      [JSON.stringify(merged), await this.id()]
    )
    this.#json = merged
  }

  async replace(replacement) {
    await db.run(
      `UPDATE object SET data = ? WHERE id = ?`,
      [JSON.stringify(replacement), await this.id()]
    )
    this.#json = replacement
  }

  async owner() {
    if (!this.#owner) {
      const row = await db.get(`SELECT owner FROM object WHERE id = ?`, [await this.id()])
      if (!row) {
        this.#owner = null;
      } else {
        this.#owner = new ActivityObject(row.owner)
      }
    }
    return this.#owner
  }

  async addressees() {
    if (!this.#addressees) {
      const id = await this.id()
      const rows = await db.all(`SELECT addresseeId FROM addressee WHERE objectId = ?`, [id])
      this.#addressees = rows.map((row) => new ActivityObject(row.addresseeId))
    }
    return this.#addressees
  }

  async canRead(subject) {

    const owner = await this.owner()
    const addressees = await this.addressees()
    const addresseeIds = await Promise.all(addressees.map((addressee) => addressee.id()))

    // anyone can read if it's public

    if (addresseeIds.includes(PUBLIC)) {
      return true;
    }
    // otherwise, unauthenticated can't read
    if (!subject) {
      return false;
    }
    // owner can always read
    if (subject === await owner.id()) {
      return true;
    }
    // direct addressees can always read
    if (addresseeIds.includes(subject)) {
      return true;
    }
    // if they're a member of any addressed collection
    for (let addresseeId of addresseeIds) {
      const obj = new ActivityObject(addresseeId)
      if (await obj.isCollection()) {
        const coll = new Collection(obj.json())
        if (await coll.hasMember(subject)) {
          return true
        }
      }
    }
    // Otherwise, can't read
    return false;
  }

  async brief() {
    const object = await this.json()
    if (!object) {
      return await this.id()
    }
    let brief = {
      id: await this.id(),
      type: await this.type(),
      icon: await this.prop('icon'),
    }
    for (let prop of ["nameMap", "name", "summaryMap", "summary"]) {
      if (prop in object) {
        brief[prop] = object[prop]
        break
      }
    }
    switch (object.type) {
      case "Key":
        brief = {
          ...brief,
          owner: object.owner,
          publicKeyPem: object.publicKeyPem
        }
        break
      case "Note":
        brief = {
          ...brief,
          content: object.content,
          contentMap: object.contentMap
        }
        break
      case "OrderedCollection":
      case "Collection":
        brief = {
          ...brief,
          first: object.first
        }
    }
    return brief
  }

  static #idProps = [
    "actor",
    "alsoKnownAs",
    "attachment",
    "attributedTo",
    "anyOf",
    "audience",
    "cc",
    "context",
    "current",
    "describes",
    "first",
    "following",
    "followers",
    "generator",
    "href",
    "icon",
    "image",
    "inbox",
    "inReplyTo",
    "instrument",
    "last",
    "liked",
    "likes",
    "location",
    "next",
    "object",
    "oneOf",
    "origin",
    "outbox",
    "partOf",
    "prev",
    "preview",
    "publicKey",
    "relationship",
    "replies",
    "result",
    "shares",
    "subject",
    "tag",
    "target",
    "to",
    "url",
  ];

  static #arrayProps = [
    'items',
    'orderedItems'
  ]

  async expanded() {
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

    for (let prop of ActivityObject.#idProps) {
      if (prop in object) {
        if (Array.isArray(object[prop])) {
          object[prop] = await Promise.all(object[prop].map(toBrief))
        } else {
          object[prop] = await toBrief(object[prop])
        }
      }
    }
    return object
  }

  async compressed() {
    const object = this.json()
    const toIdOrValue = async (value) => {
      const id = await new ActivityObject(value).id()
      if (id) {
        return id;
      } else {
        return value;
      }
    }

    for (let prop of ActivityObject.#idProps) {
      if (prop in object) {
        if(Array.isArray(object[prop])) {
          object[prop] = await Promise.all(object[prop].map(toIdOrValue))
        } else {
          object[prop] = await toIdOrValue(object[prop])
        }
      }
    }

    for (let prop of ActivityObject.#arrayProps) {
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

  static async fromActivityObject(object) {
    return new ActivityObject(await object.json())
  }

  defaultType() {
    return 'Object'
  }

  static async fromRemote(value) {
    const ao = new ActivityObject(value)
    const obj = await ao.json()
    if (!obj) {
      const id = await ao.id()
      const res = await fetch(id, {
        headers: {'Accept': 'application/activity+json, application/ld+json, application/json'}
      })
      if (res.status !== 200) {
        throw new Error(`Error fetching ${id}: ${res.status}`)
      } else {
        ao.#json = await res.json()
      }
    }
    return ao;
  }

  async needsExpandedObject() {
    return ['Create', 'Update'].includes(await this.type())
  }
}

class Activity extends ActivityObject {
  constructor(data) {
    super(data)
  }
  static async fromActivityObject(object) {
    return new Activity(await object.json())
  }

  defaultType() {
    return 'Activity'
  }

  async  apply(owner, addressees, ...args) {
    let activity = await this.json()
    const appliers = {
      "Follow": async () => {
        if (!activity.object) {
          throw new createError.BadRequest("No object followed")
        }
        const following = new Collection(owner.following)
        if (await following.hasMember(activity.object)) {
          throw new createError.BadRequest("Already following")
        }
        await following.prependData(activity.object)
        if (await isUser(activity.object)) {
          const other = new ActivityObject(activity.object)
          const followers = new Collection(await other.prop('followers'))
          if (await followers.hasMember(owner.id)) {
            throw new createError.BadRequest("Already followed")
          }
          await followers.prependData(owner)
        } else {
          // Figure out how to follow this thing
        }
        return activity
      },
      "Create": async () => {
        const object = activity.object
        if (!object) {
          throw new createError.BadRequest("No object to create")
        }
        object.attributedTo = owner.id
        object.type = object.type || "Object"
        if (!["name", "nameMap", "summary", "summaryMap"].some(p => p in object)) {
          object.summaryMap = {
            "en": `A(n) ${object.type} by ${owner.name}`
          }
        }
        const saved = new ActivityObject(object)
        await saved.save(owner.id, addressees)
        activity.object = await saved.id()
        return activity
      },
      "Update": async() => {
        if (!activity.object) {
          throw new createError.BadRequest("No object to update")
        }
        if (!activity?.object?.id) {
          throw new createError.BadRequest("No id for object to update")
        }
        let object = new ActivityObject(activity?.object?.id)
        const objectOwner = await object.owner()
        if (!objectOwner || await objectOwner.id() != owner.id) {
          throw new createError.BadRequest("You can't update an object you don't own")
        }
        await object.patch(activity.object)
        activity.object = await object.json()
        return activity
      },
      "Delete": async() => {
        if (!activity.object) {
          throw new createError.BadRequest("No object to delete")
        }
        let object = new ActivityObject(activity.object)
        if (!await object.id()) {
          throw new createError.BadRequest("No id for object to delete")
        }
        const objectOwner = await object.owner()
        if (!objectOwner || await objectOwner.id() != await toId(owner)) {
          throw new createError.BadRequest("You can't delete an object you don't own")
        }
        const timestamp = new Date().toISOString();
        await object.replace({
          id: await object.id(),
          formerType: await object.type(),
          type: "Tombstone",
          published: await object.prop('published'),
          updated: timestamp,
          deleted: timestamp,
          summaryMap: {
            "en": `A deleted ${await object.type()} by ${owner.name}`
          }
        })
        return activity
      },
      "Add": async() => {
        if (!activity.object) {
          throw new createError.BadRequest("No object to add")
        }
        let object = new ActivityObject(activity.object)
        if (!await object.id()) {
          throw new createError.BadRequest("No id for object to add")
        }
        if (!activity.target) {
          throw new createError.BadRequest("No target to add to")
        }
        let target = new Collection(activity.target)
        if (!await target.id()) {
          throw new createError.BadRequest("No id for object to add to")
        }
        if (!await target.isCollection()) {
          throw new createError.BadRequest("Can't add to a non-collection")
        }
        const targetOwner = await target.owner()
        if (!targetOwner || await targetOwner.id() != owner.id) {
          throw new createError.BadRequest("You can't add to an object you don't own")
        }
        for (let prop of ["inbox", "outbox", "followers", "following", "liked"]) {
          if (await target.id() == await toId(owner[prop])) {
            throw new createError.BadRequest(`Can't add an object directly to your ${prop}`)
          }
        }
        if (await target.hasMember(await object.id())) {
          throw new createError.BadRequest("Already a member")
        }
        await target.prepend(object)
        return activity
      },
      "Remove": async() => {
        if (!activity.object) {
          throw new createError.BadRequest("No object to remove")
        }
        let object = new ActivityObject(activity.object)
        if (!await object.id()) {
          throw new createError.BadRequest("No id for object to remove")
        }
        if (!activity.target) {
          throw new createError.BadRequest("No target to remove from")
        }
        let target = new Collection(activity.target)
        if (!await target.id()) {
          throw new createError.BadRequest("No id for object to remove from")
        }
        if (!await target.isCollection()) {
          throw new createError.BadRequest("Can't remove from a non-collection")
        }
        const targetOwner = await target.owner()
        if (!targetOwner || await targetOwner.id() != owner.id) {
          throw new createError.BadRequest("You can't remove from an object you don't own")
        }
        for (let prop of ["inbox", "outbox", "followers", "following", "liked"]) {
          if (await target.id() == await toId(owner[prop])) {
            throw new createError.BadRequest(`Can't remove an object directly from your ${prop}`)
          }
        }
        if (!await target.hasMember(await object.id())) {
          throw new createError.BadRequest("Not a member")
        }
        await target.remove(object)
        return activity
      }
    }

    if (await this.type() in appliers) {
      activity = await appliers[await this.type()]()
      this._setJson(activity)
    }
  }

  async distribute(owner, addressees) {

    const activity = await this.json()
    owner = await toObject(owner)

    // Add it to the owner inbox!

    const ownerInbox = new Collection(owner.inbox)
    await ownerInbox.prependData(activity)

    // Expand public, followers, other lists

    const expanded = (await Promise.all(addressees.map(async (addressee) => {
      if (addressee === PUBLIC) {
        const followers = new Collection(owner.followers)
        return await followers.members()
      } else {
        const obj = new ActivityObject(addressee)
        if (await obj.isCollection()) {
          const coll = new Collection(addressee)
          const objOwner = await obj.owner()
          if (coll &&
              await objOwner.id() === owner.id) {
              return await coll.members()
          }
        }
      }
      return addressee
    }))).filter((v, i, a) => v && a.indexOf(v) === i && v !== owner.id).flat()

    // Deliver to each of the expanded addressees

    const body = JSON.stringify(activity)
    const {privateKey} = await db.get('SELECT privateKey FROM user WHERE actorId = ?', [owner.id])
    const keyId = await toId(owner.publicKey)

    await Promise.all(expanded.map(async (addressee) => {
      if (await isUser(addressee)) {
        // Local delivery
        const user = new ActivityObject(addressee)
        const inbox = new Collection(await user.prop('inbox'))
        await inbox.prependData(activity)
      } else {
        const other = await getRemoteObject(addressee);
        const inbox = await toId(other.inbox)
        const date = new Date().toUTCString()
        const signature = new HTTPSignature(keyId, privateKey, 'POST', inbox, date)
        const res = await fetch(inbox, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/activity+json; charset=utf-8',
            'Signature': signature.header,
            'Date': date
          },
          body: body
        })
        const resBody = await res.text()
      }
    }))
  }
}

class Collection extends ActivityObject {
  constructor(data) {
    super(data)
  }

  static async fromActivityObject(object) {
    return new Collection(await object.json())
  }

  async hasMember(object) {
    const objectId = await toId(object)
    const collection = await this.json()
    const match = (item) => ((isString(item) && item == objectId) || ((typeof item == "object") && item.id == objectId))
    switch (collection.type) {
      case "Collection":
      case "OrderedCollection":
        if (collection.orderedItems) {
          return collection.orderedItems.some(match)
        } else if (collection.items) {
            return collection.items.some(match)
        } else if (collection.first) {
          return await (new Collection(collection.first)).hasMember(objectId)
        }
        break
      case "CollectionPage":
      case "OrderedCollectionPage":
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

  async prependData(data) {
    return this.prepend(new ActivityObject(data))
  }

  async prepend(object) {
    const collection = await this.json()
    const objectId = await object.id()
    const collectionId = await this.id()
    if (collection.orderedItems) {
      await this.patch({totalItems: collection.totalItems + 1, orderedItems: [objectId, ...collection.orderedItems]})
    } else if (collection.items) {
      await this.patch({totalItems: collection.totalItems + 1, items: [objectId, ...collection.items]})
    } else if (collection.first) {
      const first = await new ActivityObject(collection.first)
      const firstJson = await first.json()
      if (firstJson.orderedItems.length < MAX_PAGE_SIZE) {
        await first.patch({orderedItems: [objectId, ...firstJson.orderedItems]})
        await this.patch({totalItems: collection.totalItems + 1})
      } else {
        const owner = await this.owner()
        const addressees = await this.addressees()
        const newFirst = new ActivityObject({type: "OrderedCollectionPage", partOf: collection.id, 'orderedItems': [objectId], next: first.id})
        await newFirst.save(owner, addressees)
        await this.patch({totalItems: collection.totalItems + 1, first: await newFirst.id()})
        await first.patch({prev: await newFirst.id()})
      }
    }
  }

  async removeData(data) {
    return this.remove(new ActivityObject(data))
  }

  async remove(object) {
    const collection = await this.json()
    const objectId = await object.id()
    if (Array.isArray(collection.orderedItems)) {
      const i = collection.orderedItems.indexOf(objectId)
      if (i !== -1) {
        collection.orderedItems.splice(i, 1)
        await this.patch({totalItems: collection.totalItems - 1,
            orderedItems: collection.orderedItems})
      }
    } else if (Array.isArray(collection.items)) {
      const i = collection.items.indexOf(objectId)
      if (i !== -1) {
        collection.items.splice(i, 1)
        await this.patch({totalItems: collection.totalItems - 1, items: collection.items})
      }
    } else {
      let ref = collection.first
      while (ref) {
        const page = new ActivityObject(ref)
        const json = await page.json()
        for (let prop of ['items', 'orderedItems']) {
          if (json[prop]) {
            const i = json[prop].indexOf(objectId)
            if (i !== -1) {
              let patch = {}
              json[prop].splice(i, 1)
              patch[prop] = json[prop]
              await page.patch(patch)
              await this.patch({totalItems: collection.totalItems - 1})
              return
            }
          }
        }
        ref = json.next
      }
    }
    return collection
  }

  async members() {
    const obj = await this.json()
    let cur = obj.items || obj.orderedItems || [];
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

  defaultType() {
    return 'OrderedCollection'
  }
}

class RemoteActivity extends Activity {

  async save(owner, addressees) {
    const dataId = await this.id()
    const ownerId = await owner.id() || dataId
    await db.run(
      'INSERT INTO object (id, owner, data) VALUES (?, ?, ?)',
      [await dataId, ownerId, JSON.stringify(await this.json())]
    );
    await Promise.all(addressees.map((addressee) =>
      db.run(
        'INSERT INTO addressee (objectId, addresseeId) VALUES (?, ?)',
        [dataId, addressee]
      )))
  }

  async apply(remote, addressees, ...args) {
    const owner = args[0]
    const activity = await this.json()
    const remoteAppliers = {
      "Follow": async() => {
        const object = new ActivityObject(activity.object)
        if (await object.id() == toId(owner)) {
          const followers = new Collection(owner.followers)
          if (await followers.hasMember(remote)) {
            throw new Error("Already following")
          }
          await followers.prependData(remote)
        }
      },
      "Create": async() => {
        if (activity.object) {
          await cacheRemoteObject(activity.object, remote, addressees)
        }
      }
    }

    if (activity.type in remoteAppliers) {
      await remoteAppliers[activity.type]()
    }
  }
}

// Functions

const sign = promisify(jwt.sign);
const generateKeyPair = promisify(crypto.generateKeyPair);

const isString = value => typeof value === 'string' || value instanceof String;

async function toObject(value) {
  const obj = new ActivityObject(value)
  return await obj.json()
}

async function toId(value) {
  if (typeof value == "undefined") {
    return null;
  } else if (value == null) {
    return null;
  } else {
    const obj = new ActivityObject(value)
    return await obj.id()
  }
}

async function getRemoteObject(value) {
  const ao = await ActivityObject.fromRemote(value)
  return await ao.json()
}

async function cacheRemoteObject(data, owner, addressees) {
  const dataId = await toId(data)
  const ownerId = await toId(owner) || data.id
  await db.run('INSERT INTO object (id, owner, data) VALUES (?, ?, ?)', [dataId, ownerId, JSON.stringify(data)]);
  await Promise.all(addressees.map((addressee) =>
  db.run(
    'INSERT INTO addressee (objectId, addresseeId) VALUES (?, ?)',
    [dataId, addressee]
  )))
}

async function saveObject(type, data, owner=null, addressees=[]) {
  data.type = data.type || type || 'Object';
  const ao = new ActivityObject(data)
  await ao.save(owner, addressees)
  return await ao.json()
}

const emptyOrderedCollection = async(name, owner, addressees) => {
  const id = await ActivityObject.makeId('OrderedCollection')
  const page = await saveObject(
    'OrderedCollectionPage',
    {
      'orderedItems': [],
      'partOf': id
    },
    owner,
    addressees
  )
  const coll = await saveObject(
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
  return coll
}

async function isUser(object) {
  const id = await toId(object)
  const row = await db.get("SELECT username FROM user WHERE actorId = ?", [id])
  return !!row
}

// Server

// Initialize Express
const app = express();

// Initialize SQLite
const db = new Database(DATABASE);

app.use(passport.initialize()); // Initialize Passport
app.use(express.json({type: ['application/json', 'application/activity+json']})) // for parsing application/json
app.use(express.urlencoded({ extended: true })) // for HTML forms

// Local Strategy for login/logout
passport.use(new LocalStrategy(
  function(username, password, done) {

  }
));

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
    const actorId = await ActivityObject.makeId('Person')
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
    await db.run('INSERT INTO user (username, passwordHash, actorId, privateKey) VALUES (?, ?, ?, ?)', [username, passwordHash, actorId, privateKey])
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
  if (!(await ActivityObject.exists(full))) {
    throw new createError.NotFound('Object not found')
  }
  const obj = new ActivityObject(full)
  if (!(await obj.canRead(req.auth?.subject))) {
    if (req.auth?.subject) {
      throw new createError.Forbidden('Not authorized to read this object')
    } else {
      throw new createError.Unauthorized('You must provide credentials to read this object')
    }
  }
  let objType = await obj.type()
  if (objType.toLowerCase() !== type && objType !== "Tombstone") {
    throw new createError.InternalServerError('Invalid object type')
  }
  let output = await obj.expanded()
  for (let name of ['items', 'orderedItems']) {
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
  if (await obj.needsExpandedObject()) {
    const activityObject = new ActivityObject(await obj.prop('object'))
    output.object = await activityObject.expanded()
  }
  if (output.type === 'Tombstone') {
    res.status(410)
  }
  output['@context'] = output['@context'] || CONTEXT
  res.set('Content-Type', 'application/activity+json')
  res.json(output)
}))

app.post('/:type/:id',
  expressjwt({ secret: KEY_DATA, credentialsRequired: false, algorithms: ["RS256"] }),
  wrap(async(req, res) => {
  const full = req.protocol + '://' + req.get('host') + req.originalUrl;
  const obj = new ActivityObject(full)
  if (!obj) {
    throw new createError.NotFound('Object not found')
  }
  const owner = await obj.owner()
  if (!await obj.json() || !owner) {
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
    data.id = await ActivityObject.makeId(data.type || "Activity")
    data.actor = ownerId
    let activity = new Activity(data)
    await activity.apply(ownerJson, addressees)
    await activity.save(ownerId, addressees)
    await outbox.prepend(activity)
    await activity.distribute(ownerJson, addressees)
    const output = await activity.expanded()
    if (await activity.needsExpandedObject()) {
      const activityObject = new ActivityObject(await activity.prop('object'))
      output.object = await activityObject.expanded()
    }
    output['@context'] = output['@context'] || CONTEXT
    res.status(200)
    res.set('Content-Type', 'application/activity+json')
    res.json(output)
  } else if (full === await owner.prop('inbox')) { // remote delivery
    const sigHeader = req.headers['signature']
    if (!sigHeader) {
      throw new createError.Unauthorized('HTTP signature required')
    }
    const header = new HTTPSignature(sigHeader)
    const remote = await header.validate(req)
    if (!remote) {
      throw new createError.Unauthorized('Invalid HTTP signature')
    }
    if (await isUser(await remote.id())) {
      throw new createError.Forbidden('Remote delivery only')
    }
    const addressees = await Promise.all(['to', 'cc', 'bto', 'bcc']
    .map((prop) => req.body[prop])
    .filter((a) => a)
    .flat()
    .map(toId))
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
  console.error(err)
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
