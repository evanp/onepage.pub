import express from 'express'
import sqlite3 from 'sqlite3'
import passport from 'passport'
import LocalStrategy from 'passport-local'
import * as fsp from 'node:fs/promises'
import fs from 'node:fs'
import https from 'node:https'
import http from 'node:http'
import wrap from 'express-async-handler'
import createError from 'http-errors'
import { nanoid } from 'nanoid'
import bcrypt from 'bcrypt'
import { expressjwt } from 'express-jwt'
import jwt from 'jsonwebtoken'
import { promisify } from 'node:util'
import crypto from 'node:crypto'
import winston from 'winston'
import session from 'express-session'
import cookieParser from 'cookie-parser'
import querystring from 'node:querystring'
import multer from 'multer'
import mime from 'mime'
import path from 'node:path'
import { tmpdir } from 'node:os'

// Configuration

const DATABASE = process.env.OPP_DATABASE || ':memory:'
const HOSTNAME = process.env.OPP_HOSTNAME || 'localhost'
const PORT = process.env.OPP_PORT || 65380
const KEY = process.env.OPP_KEY || 'localhost.key'
const CERT = process.env.OPP_CERT || 'localhost.crt'
const LOG_LEVEL = process.env.OPP_LOG_LEVEL || 'warn'
const SESSION_SECRET =
  process.env.OPP_SESSION_SECRET || 'insecure-session-secret'
const INVITE_CODE = process.env.OPP_INVITE_CODE || null
const BLOCK_LIST = process.env.OPP_BLOCK_LIST || null
const ORIGIN =
  process.env.OPP_ORIGIN ||
  (PORT === 443 ? `https://${HOSTNAME}` : `https://${HOSTNAME}:${PORT}`)
const NAME = process.env.OPP_NAME || new URL(ORIGIN).hostname
const UPLOAD_DIR = process.env.OPP_UPLOAD_DIR || path.join(tmpdir(), nanoid())

// Ensure the Upload directory exists

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR)
}

// Calculated constants

const KEY_DATA = fs.readFileSync(KEY)
const CERT_DATA = fs.readFileSync(CERT)
const BLOCKED_DOMAINS = (() => {
  const domains = []
  if (BLOCK_LIST) {
    const data = fs.readFileSync(BLOCK_LIST, { encoding: 'utf-8' })
    const lines = data.split('\n')
    for (const line of lines) {
      const fields = line.split(',')
      domains.push(fields[0])
    }
  }
  return domains
})()

// Constants

const AS_CONTEXT = 'https://www.w3.org/ns/activitystreams'
const SEC_CONTEXT = 'https://w3id.org/security'
const BLOCKED_CONTEXT = 'https://purl.archive.org/socialweb/blocked'
const PENDING_CONTEXT = 'https://purl.archive.org/socialweb/pending'
const WEBFINGER_CONTEXT = 'https://purl.archive.org/socialweb/webfinger'
const MISCELLANY_CONTEXT = 'https://purl.archive.org/socialweb/miscellany'
const CONTEXT = [
  AS_CONTEXT,
  SEC_CONTEXT,
  BLOCKED_CONTEXT,
  PENDING_CONTEXT,
  WEBFINGER_CONTEXT,
  MISCELLANY_CONTEXT
]

const LD_MEDIA_TYPE = 'application/ld+json'
const ACTIVITY_MEDIA_TYPE = 'application/activity+json'
const JSON_MEDIA_TYPE = 'application/json'
const ACCEPT_HEADER = `${LD_MEDIA_TYPE};q=1.0, ${ACTIVITY_MEDIA_TYPE};q=0.9, ${JSON_MEDIA_TYPE};q=0.3`
const PUBLIC = 'https://www.w3.org/ns/activitystreams#Public'
const PUBLIC_OBJ = {
  id: PUBLIC,
  nameMap: { en: 'Public' },
  type: 'Collection'
}
const MAX_PAGE_SIZE = 20

// Functions

const jwtsign = promisify(jwt.sign)
const jwtverify = promisify(jwt.verify)
const generateKeyPair = promisify(crypto.generateKeyPair)

const isString = (value) =>
  typeof value === 'string' || value instanceof String

const base64URLEncode = (str) =>
  str
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')

async function toId (value) {
  if (typeof value === 'undefined') {
    return null
  } else if (value === null) {
    return null
  } else if (value instanceof ActivityObject) {
    return await value.id()
  } else if (typeof value === 'string') {
    return value
  } else if (typeof value === 'object' && 'id' in value) {
    return value.id
  } else {
    throw new Error(`Can't convert ${JSON.stringify(value)} to id`)
  }
}

function toArray (value) {
  if (typeof value === 'undefined') {
    return []
  } else if (value === null) {
    return []
  } else if (Array.isArray(value)) {
    return value
  } else {
    return [value]
  }
}

function makeUrl (relative) {
  if (relative.length > 0 && relative[0] === '/') {
    relative = relative.slice(1)
  }
  return `${ORIGIN}/${relative}`
}

function standardEndpoints () {
  return {
    proxyUrl: makeUrl('endpoint/proxyUrl'),
    oauthAuthorizationEndpoint: makeUrl('endpoint/oauth/authorize'),
    oauthTokenEndpoint: makeUrl('endpoint/oauth/token'),
    uploadMedia: makeUrl('endpoint/upload')
  }
}

function domainIsBlocked (url) {
  if (typeof url !== 'string') {
    logger.warn(`Invalid URL: ${JSON.stringify(url)}`)
    return false
  }
  let u = null
  try {
    u = new URL(url)
  } catch (err) {
    logger.warn(`Invalid URL: ${url}`)
    return false
  }
  const hostname = u.host
  return BLOCKED_DOMAINS.includes(hostname)
}

function toSpki (pem) {
  if (pem.startsWith('-----BEGIN RSA PUBLIC KEY-----')) {
    const key = crypto.createPublicKey(pem)
    pem = key.export({ type: 'spki', format: 'pem' })
  }
  return pem
}

function toPkcs8 (pem) {
  if (pem.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
    const key = crypto.createPrivateKey(pem)
    pem = key.export({ type: 'pkcs8', format: 'pem' })
  }
  return pem
}

function digestBody (body) {
  const hash = crypto.createHash('sha256')
  hash.update(body)
  return `sha-256=${hash.digest('base64')}`
}

// Classes

class Database {
  #path = null
  #db = null
  constructor (path) {
    this.#path = path
    this.#db = new sqlite3.Database(this.#path)
  }

  async init () {
    await this.run(
      'CREATE TABLE IF NOT EXISTS user (username VARCHAR(255) PRIMARY KEY, passwordHash VARCHAR(255), actorId VARCHAR(255), privateKey TEXT)'
    )
    await this.run(
      'CREATE TABLE IF NOT EXISTS object (id VARCHAR(255) PRIMARY KEY, owner VARCHAR(255), data TEXT)'
    )
    await this.run(
      'CREATE TABLE IF NOT EXISTS addressee (objectId VARCHAR(255), addresseeId VARCHAR(255))'
    )
    await this.run(
      'CREATE TABLE IF NOT EXISTS upload (relative VARCHAR(255), mediaType VARCHAR(255), objectId VARCHAR(255))'
    )
    await this.run(
      'CREATE TABLE IF NOT EXISTS server (origin VARCHAR(255) PRIMARY KEY, privateKey TEXT, publicKey TEXT)'
    )

    // Create the public key for this server if it doesn't exist

    await Server.ensureKey()
  }

  async run (...params) {
    logger.silly('run() SQL: ' + params[0], params.slice(1))
    return new Promise((resolve, reject) => {
      this.#db.run(...params, (err, results) => {
        if (err) {
          reject(err)
        } else {
          resolve(results)
        }
      })
    })
  }

  async get (...params) {
    logger.silly('get() SQL: ' + params[0], params.slice(1))
    return new Promise((resolve, reject) => {
      this.#db.get(...params, (err, results) => {
        if (err) {
          reject(err)
        } else {
          resolve(results)
        }
      })
    })
  }

  async all (...params) {
    logger.silly('all() SQL: ' + params[0], params.slice(1))
    return new Promise((resolve, reject) => {
      this.#db.all(...params, (err, results) => {
        if (err) {
          reject(err)
        } else {
          resolve(results)
        }
      })
    })
  }

  async close () {
    return new Promise((resolve, reject) => {
      this.#db.close((err) => {
        if (err) {
          reject(err)
        } else {
          resolve()
        }
      })
    })
  }

  async ready () {
    try {
      const value = await this.get('SELECT 1')
      return !!value
    } catch (err) {
      return false
    }
  }
}

class HTTPSignature {
  constructor (
    keyId,
    privateKey = null,
    method = null,
    url = null,
    date = null,
    digest = null
  ) {
    if (!privateKey) {
      const sigHeader = keyId
      const parts = Object.fromEntries(
        sigHeader.split(',').map((clause) => {
          const match = clause.match(/^\s*(\w+)\s*=\s*"(.*?)"\s*$/)
          return [match[1], match[2].replace(/\\"/, '"')]
        })
      )
      if (
        !parts.keyId ||
        !parts.headers ||
        !parts.signature ||
        !parts.algorithm
      ) {
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
      this.url = isString(url) ? new URL(url) : url
      this.date = date
      this.digest = digest
      this.signature = this.sign(this.signableData())
      this.header = `keyId="${this.keyId}",headers="(request-target) host date${
        this.digest ? ' digest' : ''
      }",signature="${this.signature.replace(
        /"/g,
        '\\"'
      )}",algorithm="rsa-sha256"`
    }
  }

  signableData () {
    const target =
      this.url.search && this.url.search.length
        ? `${this.url.pathname}?${this.url.search}`
        : `${this.url.pathname}`
    let data = `(request-target): ${this.method.toLowerCase()} ${target}\n`
    data += `host: ${this.url.host}\n`
    data += `date: ${this.date}`
    if (this.digest) {
      data += `\ndigest: ${this.digest}`
    }
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
        lines.push(
          `(request-target): ${req.method.toLowerCase()} ${req.originalUrl}`
        )
      } else {
        const value = req.get(name)
        lines.push(`${name}: ${value}`)
      }
    }
    const data = lines.join('\n')
    const url = new URL(this.keyId)
    const fragment = url.hash ? url.hash.slice(1) : null
    url.hash = ''

    const ao = await ActivityObject.get(url.toString())
    let publicKey = null

    // Mastodon uses 'main-key' instead of 'publicKey'

    if (!fragment) {
      publicKey = ao
    } else if (fragment in (await ao.json())) {
      publicKey = await ActivityObject.get(await ao.prop(fragment), [
        'publicKeyPem',
        'owner'
      ])
    } else if (fragment === 'main-key' && 'publicKey' in (await ao.json())) {
      publicKey = await ActivityObject.get(await ao.prop('publicKey'), [
        'publicKeyPem',
        'owner'
      ])
    } else {
      return null
    }

    if (
      !(await publicKey.json()) ||
      !(await publicKey.prop('owner')) ||
      !(await publicKey.prop('publicKeyPem'))
    ) {
      return null
    }

    const verifier = crypto.createVerify('sha256')
    verifier.write(data)
    verifier.end()

    if (
      verifier.verify(
        await publicKey.prop('publicKeyPem'),
        Buffer.from(this.signature, 'base64')
      )
    ) {
      const ownerId = await publicKey.prop('owner')
      const owner = await ActivityObject.get(ownerId)
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
      } else {
        next(new createError.Unauthorized('Invalid HTTP signature'))
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
      this.count++
      this.last = this.last
        .then(() => {
          return operation
        })
        .then((...args) => {
          this.count--
          resolve(...args)
        })
        .catch((err) => {
          this.count--
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
  #complete = false
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
    const best = ActivityObject.bestType(type)
    if (best) {
      return makeUrl(`${best.toLowerCase()}/${nanoid()}`)
    } else {
      return makeUrl(`object/${nanoid()}`)
    }
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

  static async get (ref, props = null, subject = null) {
    if (props && !Array.isArray(props)) {
      throw new Error(`Invalid props: ${JSON.stringify(props)}`)
    }
    if (typeof ref === 'string') {
      return await ActivityObject.getById(ref, subject)
    } else if (typeof ref === 'object') {
      if (ref instanceof ActivityObject) {
        return ref
      } else if (
        props &&
        props.every((prop) =>
          Array.isArray(prop) ? prop.some((p) => p in ref) : prop in ref
        )
      ) {
        return new ActivityObject(ref)
      } else if ('id' in ref) {
        return await ActivityObject.getById(ref.id, subject)
      } else {
        throw new Error(`Can't get object from ${JSON.stringify(ref)}`)
      }
    }
  }

  static async getById (id, subject = null) {
    if (id === PUBLIC) {
      return new ActivityObject(PUBLIC_OBJ)
    }
    const obj = await ActivityObject.getFromDatabase(id, subject)
    if (obj) {
      return obj
    } else if (ActivityObject.isRemoteId(id)) {
      return await ActivityObject.getFromRemote(id, subject)
    } else {
      return null
    }
  }

  static async getFromDatabase (id, subject = null) {
    const row = await db.get('SELECT data FROM object WHERE id = ?', [id])
    if (!row) {
      return null
    } else {
      const obj = new ActivityObject(JSON.parse(row.data))
      obj.#complete = true
      return obj
    }
  }

  static async getFromRemote (id, subject = null) {
    const date = new Date().toISOString()
    const headers = {
      Date: date,
      Accept: ACCEPT_HEADER
    }
    let keyId = null
    let privKey = null
    if (subject && (await User.isUser(subject))) {
      const user = await User.fromActorId(await toId(subject))
      const subjectObj = await ActivityObject.get(
        subject,
        ['publicKey'],
        subject
      )
      keyId = await toId(await subjectObj.prop('publicKey'))
      privKey = user.privateKey
    } else {
      const server = await Server.get()
      keyId = server.keyId()
      privKey = server.privateKey()
    }
    const signature = new HTTPSignature(keyId, privKey, 'GET', id, date)
    headers.Signature = signature.header
    const res = await fetch(id, { headers })
    if (res.status !== 200) {
      logger.warn(`Error fetching ${id}: ${res.status} ${res.statusText}`)
      return null
    } else {
      const json = await res.json()
      const obj = new ActivityObject(json)
      const owner = ActivityObject.guessOwner(json)
      const addressees = ActivityObject.guessAddressees(json)
      obj.#complete = true
      await obj.cache(owner, addressees)
      return obj
    }
  }

  static guessOwner (json) {
    for (const prop of ['attributedTo', 'actor', 'owner']) {
      if (prop in json) {
        return json[prop]
      }
    }
    return null
  }

  static guessAddressees (json) {
    let addressees = []
    for (const prop of ['to', 'cc', 'bto', 'bcc', 'audience']) {
      if (prop in json) {
        addressees = addressees.concat(toArray(json[prop]))
      }
    }
    return addressees
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
    if (!this.#id) {
      this.#id = await this.prop('id')
    }
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

  async setProp (name, value) {
    const json = await this.json()
    if (json) {
      json[name] = value
      this.#json = json
    } else {
      this.#json = { [name]: value }
    }
  }

  async expand () {
    const json = await this.expanded()
    this.#json = json
    return this.#json
  }

  async isCollection () {
    return ['Collection', 'OrderedCollection'].includes(await this.type())
  }

  async isCollectionPage () {
    return ['CollectionPage', 'OrderedCollectionPage'].includes(
      await this.type()
    )
  }

  async save (owner = null, addressees = null) {
    const data = await this.compressed()
    if (!owner) {
      owner = ActivityObject.guessOwner(data)
    }
    if (!addressees) {
      addressees = ActivityObject.guessAddressees(data)
    }
    data.type = data.type || this.defaultType()
    data.id = data.id || (await ActivityObject.makeId(data.type))
    data.updated = new Date().toISOString()
    data.published = data.published || data.updated
    // self-ownership
    const ownerId = (await toId(owner)) || data.id
    const addresseeIds = await Promise.all(
      addressees.map((addressee) => toId(addressee))
    )
    await db.run('INSERT INTO object (id, owner, data) VALUES (?, ?, ?)', [
      data.id,
      ownerId,
      JSON.stringify(data)
    ])
    await Promise.all(
      addresseeIds.map((addresseeId) =>
        db.run('INSERT INTO addressee (objectId, addresseeId) VALUES (?, ?)', [
          data.id,
          addresseeId
        ])
      )
    )
    this.#id = data.id
    this.#json = data
  }

  static #coreTypes = [
    'Object',
    'Link',
    'Activity',
    'IntransitiveActivity',
    'Collection',
    'OrderedCollection',
    'CollectionPage',
    'OrderedCollectionPage'
  ]

  static #activityTypes = [
    'Accept',
    'Add',
    'Announce',
    'Arrive',
    'Block',
    'Create',
    'Delete',
    'Dislike',
    'Flag',
    'Follow',
    'Ignore',
    'Invite',
    'Join',
    'Leave',
    'Like',
    'Listen',
    'Move',
    'Offer',
    'Question',
    'Reject',
    'Read',
    'Remove',
    'TentativeReject',
    'TentativeAccept',
    'Travel',
    'Undo',
    'Update',
    'View'
  ]

  static #actorTypes = [
    'Application',
    'Group',
    'Organization',
    'Person',
    'Service'
  ]

  static #objectTypes = [
    'Article',
    'Audio',
    'Document',
    'Event',
    'Image',
    'Note',
    'Page',
    'Place',
    'Profile',
    'Relationship',
    'Tombstone',
    'Video'
  ]

  static #linkTypes = ['Mention']

  static #knownTypes = [].concat(
    ActivityObject.#coreTypes,
    ActivityObject.#activityTypes,
    ActivityObject.#actorTypes,
    ActivityObject.#objectTypes,
    ActivityObject.#linkTypes
  )

  static bestType (type) {
    const types = Array.isArray(type) ? type : [type]
    for (const item of types) {
      if (item in ActivityObject.#knownTypes) {
        return item
      }
    }
    // TODO: more filtering here?
    return types[0]
  }

  static isActivityType (type) {
    const types = Array.isArray(type) ? type : [type]
    return types.some((t) => {
      return (
        ['Activity', 'IntransitiveActivity'].includes(t) ||
        ActivityObject.#activityTypes.includes(t)
      )
    })
  }

  static isObjectType (type) {
    const types = Array.isArray(type) ? type : [type]
    return types.some((t) => {
      return (
        [
          'Object',
          'Link',
          'Collection',
          'CollectionPage',
          'OrderedCollection',
          'OrderedCollectionPage'
        ].includes(t) || ActivityObject.#objectTypes.includes(t)
      )
    })
  }

  async cache (owner = null, addressees = null) {
    const dataId = await this.id()
    const data = await this.json()
    if (!owner) {
      owner = ActivityObject.guessOwner(data)
    }
    if (!addressees) {
      addressees = ActivityObject.guessAddressees(data)
    }
    const ownerId = (await toId(owner)) || data.id
    const addresseeIds = await Promise.all(
      addressees.map((addressee) => toId(addressee))
    )
    const qry =
      'INSERT OR REPLACE INTO object (id, owner, data) VALUES (?, ?, ?)'
    await db.run(qry, [dataId, ownerId, JSON.stringify(data)])
    await Promise.all(
      addresseeIds.map(
        async (addresseeId) =>
          await db.run(
            'INSERT OR IGNORE INTO addressee (objectId, addresseeId) VALUES (?, ?)',
            [dataId, await toId(addresseeId)]
          )
      )
    )
  }

  async patch (patch) {
    const merged = {
      ...(await this.json()),
      ...patch,
      updated: new Date().toISOString()
    }
    // null means delete
    for (const prop in patch) {
      if (patch[prop] == null) {
        delete merged[prop]
      }
    }
    await db.run('UPDATE object SET data = ? WHERE id = ?', [
      JSON.stringify(merged),
      await this.id()
    ])
    this.#json = merged
  }

  async replace (replacement) {
    await db.run('UPDATE object SET data = ? WHERE id = ?', [
      JSON.stringify(replacement),
      await this.id()
    ])
    this.#json = replacement
  }

  async owner () {
    if (!this.#owner) {
      const row = await db.get('SELECT owner FROM object WHERE id = ?', [
        await this.id()
      ])
      if (!row) {
        this.#owner = null
      } else {
        this.#owner = await ActivityObject.get(row.owner)
      }
    }
    return this.#owner
  }

  async addressees () {
    if (!this.#addressees) {
      const id = await this.id()
      const rows = await db.all(
        'SELECT addresseeId FROM addressee WHERE objectId = ?',
        [id]
      )
      this.#addressees = await Promise.all(
        rows.map((row) => ActivityObject.get(row.addresseeId))
      )
    }
    return this.#addressees
  }

  async canRead (subject) {
    const owner = await this.owner()
    const addressees = await this.addressees()
    const addresseeIds = await Promise.all(
      addressees.map((addressee) => addressee.id())
    )
    if (subject && typeof subject !== 'string') {
      throw new Error(`Unexpected subject: ${JSON.stringify(subject)}`)
    }
    // subjects from blocked domains can never read
    if (subject && domainIsBlocked(subject)) {
      return false
    }
    if (subject && (await User.isUser(owner))) {
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
    if (subject === (await owner.id())) {
      return true
    }
    // direct addressees can always read
    if (addresseeIds.includes(subject)) {
      return true
    }
    // if they're a member of any addressed collection
    for (const addresseeId of addresseeIds) {
      const obj = await ActivityObject.get(addresseeId)
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
    if (subject === (await owner.id())) {
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

  static #arrayProps = ['items', 'orderedItems']

  async expanded () {
    // force a full read
    const id = await this.id()
    if (!id) {
      throw new Error('No id for object being expanded')
    }
    const ao = await ActivityObject.getById(id)
    if (!ao) {
      throw new Error(`No such object: ${id}`)
    }
    const object = await ao.json()
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
        } else if (prop === 'object' && (await this.needsExpandedObject())) {
          object[prop] = await new ActivityObject(object[prop]).expanded()
        } else {
          object[prop] = await toBrief(object[prop])
        }
      }
    }

    // Fix for PKCS1 format public keys
    if ('publicKeyPem' in object) {
      object.publicKeyPem = toSpki(object.publicKeyPem)
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

  async needsExpandedObject () {
    const needs = ['Create', 'Update', 'Accept', 'Reject', 'Announce']
    const type = await this.type()
    const types = Array.isArray(type) ? type : [type]
    return types.some((t) => needs.includes(t))
  }

  async hasProp (prop) {
    const json = await this.json()
    return prop in json
  }

  static isRemoteId (id) {
    return !id.startsWith(ORIGIN)
  }

  static async copyAddresseeProps (to, from) {
    for (const prop of ['to', 'cc', 'bto', 'bcc', 'audience']) {
      const toValues = toArray(to[prop])
      const fromValues = toArray(from[prop])
      const merged = [...toValues, ...fromValues]
      const ids = await Promise.all(merged.map((addressee) => toId(addressee)))
      const unique = [...new Set(ids)]
      if (unique.length > 0) {
        to[prop] = unique
      }
    }
  }

  async ensureAddressee (addressee) {
    const id = await toId(addressee)
    const addressees = await this.addressees()
    for (const a of addressees) {
      if ((await a.id()) === id) {
        return
      }
    }
    await db.run(
      'INSERT INTO addressee (objectId, addresseeId) VALUES (?, ?)',
      [await this.id(), id]
    )
  }
}

class Activity extends ActivityObject {
  static async fromActivityObject (object) {
    return new Activity(await object.json())
  }

  defaultType () {
    return 'Activity'
  }

  async apply () {
    let activity = await this.json()
    const actor = await ActivityObject.guessOwner(activity)
    const addressees = ActivityObject.guessAddressees(activity)
    const actorObj = await ActivityObject.get(
      actor,
      ['followers', 'following', 'pendingFollowers', 'pendingFollowing'],
      actor
    )
    const appliers = {
      Follow: async () => {
        const objectProp = await this.prop('object')
        if (!objectProp) {
          throw new createError.BadRequest('No object followed')
        }
        const other = await ActivityObject.get(objectProp, null, actorObj)
        if (!other) {
          throw new createError.BadRequest(
            `No such object to follow: ${JSON.stringify(objectProp)}`
          )
        }
        await other.expand()
        const otherId = await other.id()
        const following = new Collection(await actorObj.prop('following'))
        if (await following.hasMember(otherId)) {
          throw new createError.BadRequest('Already following')
        }
        const pendingFollowing = new Collection(
          await actorObj.prop('pendingFollowing')
        )
        if (
          await pendingFollowing.find(
            async (act) => (await toId(await act.prop('object'))) === otherId
          )
        ) {
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
          pendingFollowers = new Collection(
            await other.prop('pendingFollowers')
          )
          if (
            await pendingFollowers.find(
              async (act) => (await toId(await act.prop('object'))) === actorId
            )
          ) {
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
          throw new createError.BadRequest('No object accepted')
        }
        const accepted = await ActivityObject.get(
          objectProp,
          [['id', '@id'], 'actor', 'type'],
          actorObj
        )
        switch (await accepted.type()) {
          case 'Follow': {
            const pendingFollowers = new Collection(
              await actorObj.prop('pendingFollowers')
            )
            await pendingFollowers.expand()
            if (!(await pendingFollowers.hasMember(await accepted.id()))) {
              throw new createError.BadRequest(
                'Not awaiting acceptance for follow'
              )
            }
            const other = await ActivityObject.get(
              await accepted.prop('actor'),
              [['id', '@id'], 'type', 'pendingFollowing', 'following'],
              actorObj
            )
            const isUser = await User.isUser(other)
            let pendingFollowing = null
            if (isUser) {
              pendingFollowing = new Collection(
                await other.prop('pendingFollowing')
              )
              await pendingFollowers.expand()
              if (!(await pendingFollowing.hasMember(await accepted.id()))) {
                throw new createError.BadRequest(
                  'Not awaiting acceptance for follow'
                )
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
        const rejected = await ActivityObject.get(
          objectProp,
          ['id', 'type', 'actor'],
          actorObj
        )
        switch (await rejected.type()) {
          case 'Follow': {
            const pendingFollowers = new Collection(
              await actorObj.prop('pendingFollowers')
            )
            if (!(await pendingFollowers.hasMember(await rejected.id()))) {
              throw new createError.BadRequest(
                'Not awaiting acceptance for follow'
              )
            }
            const other = await ActivityObject.get(
              await rejected.prop('actor'),
              ['pendingFollowing'],
              actorObj
            )
            const isUser = await User.isUser(other)
            let pendingFollowing = null
            if (isUser) {
              pendingFollowing = new Collection(
                await other.prop('pendingFollowing')
              )
              if (!(await pendingFollowing.hasMember(await rejected.id()))) {
                throw new createError.BadRequest(
                  'Not awaiting acceptance for follow'
                )
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
        object.attributedTo = await actorObj.id()
        await ActivityObject.copyAddresseeProps(object, activity)
        await ActivityObject.copyAddresseeProps(activity, object)
        object.type = object.type || 'Object'
        const summaryEn = `A(n) ${object.type} by ${await actorObj.name()}`
        if (
          !['name', 'nameMap', 'summary', 'summaryMap'].some((p) => p in object)
        ) {
          object.summaryMap = {
            en: summaryEn
          }
        }
        for (const prop of ['likes', 'replies', 'shares']) {
          const value = await Collection.empty(
            await actorObj.id(),
            addressees,
            { summaryMap: { en: `${prop} of ${summaryEn}` } }
          )
          object[prop] = await value.id()
        }
        // Add paging setup for collections
        const types = Array.isArray(object.type) ? object.type : [object.type]
        if (
          types.some((t) => ['Collection', 'OrderedCollection'].includes(t)) &&
          !('items' in object) &&
          !('orderedItems' in object)
        ) {
          object.id = await ActivityObject.makeId(object.type)
          const pageProps =
            'OrderedCollection' in types
              ? { type: 'OrderedCollectionPage', orderedItems: [] }
              : { type: 'CollectionPage', items: [] }
          const page = new ActivityObject({
            partOf: object.id,
            attributedTo: await actorObj.id(),
            ...pageProps
          })
          await ActivityObject.copyAddresseeProps(page, object)
          await page.save()
          object.first = object.last = await page.id()
        }
        const saved = new ActivityObject(object)
        await saved.save()
        activity.object = await saved.id()
        if (await saved.prop('inReplyTo')) {
          const inReplyToProp = await saved.prop('inReplyTo')
          const parent = await ActivityObject.get(
            inReplyToProp,
            ['id', 'replies'],
            actorObj
          )
          const parentOwner = await parent.owner()
          if (parentOwner && (await User.isUser(parentOwner))) {
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
        const object = await ActivityObject.getById(
          activity.object.id,
          actorObj
        )
        if (!object) {
          throw new createError.BadRequest(
            `Unable to get object ${activity.object.id}`
          )
        }
        const objectOwner = await object.owner()
        if (
          !objectOwner ||
          (await objectOwner.id()) !== (await actorObj.id())
        ) {
          throw new createError.BadRequest(
            "You can't update an object you don't own"
          )
        }
        // prevent updating certain properties directly
        if (await User.isUser(object)) {
          for (const prop of [
            'inbox',
            'outbox',
            'followers',
            'following',
            'pendingFollowers',
            'pendingFollowing',
            'liked',
            'blocked'
          ]) {
            if (
              prop in activity.object &&
              (await toId(activity.object[prop])) !==
                (await toId(await object.prop(prop)))
            ) {
              throw new createError.BadRequest(
                `Cannot update ${prop} directly`
              )
            }
          }
        }
        // prevent updating collection properties directly
        if (await object.isCollection()) {
          for (const prop of ['first', 'last', 'current']) {
            if (
              prop in activity.object &&
              (await toId(activity.object[prop])) !==
                (await toId(await object.prop(prop)))
            ) {
              throw new createError.BadRequest(
                `Cannot update ${prop} directly`
              )
            }
          }
          for (const prop of ['totalItems']) {
            if (
              prop in activity.object &&
              activity.object[prop] !== (await object.prop(prop))
            ) {
              throw new createError.BadRequest(
                `Cannot update ${prop} directly`
              )
            }
          }
        }
        // prevent updating collection properties directly
        if (await object.isCollectionPage()) {
          for (const prop of ['prev', 'next', 'partOf']) {
            if (
              prop in activity.object &&
              (await toId(activity.object[prop])) !==
                (await toId(await object.prop(prop)))
            ) {
              throw new createError.BadRequest(
                `Cannot update ${prop} directly`
              )
            }
          }
          for (const prop of ['startIndex']) {
            if (
              prop in activity.object &&
              activity.object[prop] !== (await object.prop(prop))
            ) {
              throw new createError.BadRequest(
                `Cannot update ${prop} directly`
              )
            }
          }
        }
        // Common between page and collection
        if (
          (await object.isCollection()) ||
          (await object.isCollectionPage())
        ) {
          for (const prop of ['items', 'orderedItems']) {
            if (prop in activity.object) {
              const proposed = activity.object[prop]
              const current = await object.prop(prop)
              if (!current) {
                throw new createError.BadRequest(
                  `Cannot insert ${prop} directly`
                )
              }
              if (!Array.isArray(proposed)) {
                throw new createError.BadRequest(
                  `Cannot insert scalar value for ${prop}`
                )
              }
              if (proposed.length !== current.length) {
                throw new createError.BadRequest(
                  `Cannot change size of ${prop}`
                )
              }
              for (const i in current) {
                if (proposed[i] !== current[i]) {
                  throw new createError.BadRequest(
                    `Cannot change values of ${prop}`
                  )
                }
              }
            }
          }
        }
        // prevent updating object properties directly
        for (const prop of ['replies', 'likes', 'shares', 'attributedTo']) {
          if (
            prop in activity.object &&
            (await toId(activity.object[prop])) !==
              (await toId(await object.prop(prop)))
          ) {
            throw new createError.BadRequest(`Cannot update ${prop} directly`)
          }
        }
        // prevent updating non-object properties directly
        for (const prop of ['published', 'updated']) {
          if (
            prop in activity.object &&
            activity.object[prop] !== (await object.prop(prop))
          ) {
            logger.debug(
              `Update mismatch for ${prop}: ${
                activity.object[prop]
              } !== ${await object.prop(prop)} `
            )
            throw new createError.BadRequest(`Cannot update ${prop} directly`)
          }
        }
        await object.patch(activity.object)
        activity.object = await object.json()
        return activity
      },
      Delete: async () => {
        if (!activity.object) {
          throw new createError.BadRequest('No object to delete')
        }
        const object = await ActivityObject.get(
          activity.object,
          ['id', 'type'],
          actorObj
        )
        if (!(await object.id())) {
          throw new createError.BadRequest('No id for object to delete')
        }
        const objectOwner = await object.owner()
        if (!objectOwner || (await objectOwner.id()) !== (await toId(actor))) {
          throw new createError.BadRequest(
            "You can't delete an object you don't own"
          )
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
            en: `A deleted ${await object.type()} by ${await actorObj.name()}`
          }
        })
        return activity
      },
      Add: async () => {
        if (!activity.object) {
          throw new createError.BadRequest('No object to add')
        }
        const object = await ActivityObject.get(
          activity.object,
          ['id', 'type'],
          actorObj
        )
        if (!(await object.id())) {
          throw new createError.BadRequest('No id for object to add')
        }
        if (!activity.target) {
          throw new createError.BadRequest('No target to add to')
        }
        const target = new Collection(activity.target)
        if (!(await target.id())) {
          throw new createError.BadRequest('No id for object to add to')
        }
        if (!(await target.isCollection())) {
          throw new createError.BadRequest("Can't add to a non-collection")
        }
        const targetOwner = await target.owner()
        if (
          !targetOwner ||
          (await targetOwner.id()) !== (await actorObj.id())
        ) {
          throw new createError.BadRequest(
            "You can't add to an object you don't own"
          )
        }
        for (const prop of [
          'inbox',
          'outbox',
          'followers',
          'following',
          'liked'
        ]) {
          if ((await target.id()) === (await toId(actor[prop]))) {
            throw new createError.BadRequest(
              `Can't add an object directly to your ${prop}`
            )
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
        const object = await ActivityObject.get(
          activity.object,
          ['id', 'type'],
          actorObj
        )
        if (!(await object.id())) {
          throw new createError.BadRequest('No id for object to remove')
        }
        if (!activity.target) {
          throw new createError.BadRequest('No target to remove from')
        }
        const target = new Collection(activity.target)
        if (!(await target.id())) {
          throw new createError.BadRequest('No id for object to remove from')
        }
        if (!(await target.isCollection())) {
          throw new createError.BadRequest(
            "Can't remove from a non-collection"
          )
        }
        const targetOwner = await target.owner()
        if (
          !targetOwner ||
          (await targetOwner.id()) !== (await actorObj.id())
        ) {
          throw new createError.BadRequest(
            "You can't remove from an object you don't own"
          )
        }
        for (const prop of [
          'inbox',
          'outbox',
          'followers',
          'following',
          'liked'
        ]) {
          if ((await target.id()) === (await toId(actor[prop]))) {
            throw new createError.BadRequest(
              `Can't remove an object directly from your ${prop}`
            )
          }
        }
        if (!(await target.hasMember(await object.id()))) {
          throw new createError.BadRequest('Not a member')
        }
        await target.remove(object)
        return activity
      },
      Like: async () => {
        if (!activity.object) {
          throw new createError.BadRequest('No object to like')
        }
        const object = await ActivityObject.get(
          activity.object,
          ['id', 'type', 'likes'],
          actorObj
        )
        if (!(await object.canRead(await actorObj.id()))) {
          throw new createError.BadRequest(
            "Can't like an object you can't read"
          )
        }
        const liked = new Collection(await actorObj.prop('liked'))
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
        if (!(await this.prop('object'))) {
          throw new createError.BadRequest('No object to block')
        }
        const blocked = new Collection(await actorObj.prop('blocked'))
        const other = await ActivityObject.get(
          await this.prop('object'),
          ['id', 'type', 'followers', 'following'],
          actorObj
        )
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
        if (!(await this.prop('object'))) {
          throw new createError.BadRequest('Nothing to announce')
        }
        const object = await ActivityObject.get(
          await this.prop('object'),
          ['id', 'type', 'shares'],
          actorObj
        )
        const owner = await object.owner()
        if (await User.isUser(owner)) {
          const shares = new Collection(await object.prop('shares'))
          await shares.prepend(this)
        }
        return activity
      },
      Undo: async () => {
        if (!(await this.prop('object'))) {
          throw new createError.BadRequest('Nothing to undo')
        }
        const object = await ActivityObject.get(
          await this.prop('object'),
          ['object', 'type', 'id'],
          actorObj
        )
        const owner = await object.owner()
        if ((await owner.id()) !== (await actorObj.id())) {
          throw new createError.BadRequest(
            'Cannot undo an object you do not own'
          )
        }
        switch (await object.type()) {
          case 'Like': {
            if (!(await object.prop('object'))) {
              throw new createError.BadRequest('Nothing liked')
            }
            const likedObject = await ActivityObject.get(
              await object.prop('object'),
              ['id', 'type', 'likes'],
              actorObj
            )
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
            if (!(await object.prop('object'))) {
              throw new createError.BadRequest('Nothing blocked')
            }
            const blockedObject = await ActivityObject.get(
              await object.prop('object'),
              null,
              actorObj
            )
            const blocked = new Collection(await actorObj.prop('blocked'))
            await blocked.remove(blockedObject)
            break
          }
          case 'Follow': {
            if (!(await object.prop('object'))) {
              throw new createError.BadRequest('Nothing followed')
            }
            const followedObject = await ActivityObject.get(
              await object.prop('object'),
              ['id', 'type', 'followers'],
              actorObj
            )
            const pendingFollowing = new Collection(
              await actorObj.prop('pendingFollowing')
            )
            if (await pendingFollowing.hasMember(await object.id())) {
              await pendingFollowing.remove(object)
            } else {
              const following = new Collection(
                await actorObj.prop('following')
              )
              await following.remove(followedObject)
            }
            const followedObjectOwner = await followedObject.owner()
            if (
              followedObjectOwner &&
              (await User.isUser(followedObjectOwner))
            ) {
              const pendingFollowers = new Collection(
                await followedObjectOwner.prop('pendingFollowers')
              )
              if (await pendingFollowers.hasMember(await object.id())) {
                await pendingFollowers.remove(object)
              } else {
                const followers = new Collection(
                  await followedObject.prop('followers')
                )
                await followers.remove(actorObj)
              }
            }
            break
          }
          case 'Announce': {
            if (!(await object.prop('object'))) {
              throw new createError.BadRequest('Nothing announced')
            }
            const sharedObject = await ActivityObject.get(
              await object.prop('object'),
              ['id', 'type', 'shares'],
              actorObj
            )
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
    const type = await this.type()
    const types = Array.isArray(type) ? type : [type]
    for (const item of types) {
      if (item in appliers) {
        activity = await appliers[item]()
        this._setJson(activity)
      }
    }
  }

  async distribute (addressees = null) {
    const owner = await this.owner()
    const activity = await this.expanded()
    if (!addressees) {
      addressees = ActivityObject.guessAddressees(activity)
    }

    addressees = await Promise.all(
      addressees.map(async (addressee) => toId(addressee))
    )

    // Expand public, followers, other lists

    const expanded = (
      await Promise.all(
        addressees.map(async (addressee) => {
          if (addressee === PUBLIC) {
            const followers = new Collection(await owner.prop('followers'))
            return await followers.members()
          } else {
            const obj = new ActivityObject(addressee)
            if (await obj.isCollection()) {
              const coll = new Collection(addressee)
              const objOwner = await obj.owner()
              if (coll && (await objOwner.id()) === (await owner.id())) {
                return await coll.members()
              }
            }
          }
          return addressee
        })
      )
    )
      .filter((v, i, a) => v && a.indexOf(v) === i && v !== owner.id)
      .flat()

    // Deliver to each of the expanded addressees

    const body = JSON.stringify(activity)
    const { privateKey } = await db.get(
      'SELECT privateKey FROM user WHERE actorId = ?',
      [await owner.id()]
    )
    const keyId = await toId(await owner.prop('publicKey'))

    const sendTo = async (addressee) => {
      let other = await ActivityObject.get(addressee, null, owner)
      if (await User.isUser(other)) {
        // Local delivery
        await other.expand()
        logger.debug(`Local delivery for ${activity.id} to ${addressee}`)
        const inbox = new Collection(await other.prop('inbox'))
        await inbox.prependData(activity)
      } else {
        logger.debug(`Remote delivery for ${activity.id} to ${addressee}`)
        other = await ActivityObject.get(addressee)
        const inboxProp = await other.prop('inbox')
        if (!inboxProp) {
          logger.warn(`Cannot deliver to ${addressee}: no 'inbox' property`)
          return
        }
        const inbox = await toId(inboxProp)
        const date = new Date().toUTCString()
        const digest = digestBody(body)
        const signature = new HTTPSignature(
          keyId,
          privateKey,
          'POST',
          inbox,
          date,
          digest
        )
        try {
          const res = await fetch(inbox, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/activity+json; charset=utf-8',
              Signature: signature.header,
              Date: date,
              Digest: digest
            },
            body
          })
          const resBody = await res.text()
          if (res.statusCode < 200 || res.statusCode >= 300) {
            throw new Error(
              `Bad status ${res.statusCode} for delivery to ${inbox}: ${resBody}`
            )
          }
        } catch (err) {
          logger.warn(`Failed delivery to ${inbox}: ${err.message}`)
          throw err
        }
      }
    }

    for (const addressee of expanded) {
      pq.add(sendTo(addressee))
    }
  }

  static duckType (data) {
    const props = [
      'actor',
      'object',
      'target',
      'result',
      'origin',
      'instrument'
    ]
    return props.some((p) => p in data)
  }

  async setActor (actor) {
    await this.setProp('actor', await toId(actor))
  }
}

class Collection extends ActivityObject {
  static async get (id, props = null, actor = null) {
    const ao = await super.get(id, props, actor)
    if (ao) {
      return Collection.fromActivityObject(ao)
    } else {
      return null
    }
  }

  static async fromActivityObject (object) {
    const coll = new Collection(await object.json())
    return coll
  }

  async hasMember (object) {
    await this.expand()
    const objectId = await toId(object)
    const match = (item) =>
      (isString(item) && item === objectId) ||
      (typeof item === 'object' && item.id === objectId)
    if (await this.hasProp('orderedItems')) {
      const orderedItems = await this.prop('orderedItems')
      return orderedItems.some(match)
    } else if (await this.hasProp('items')) {
      const items = await this.prop('items')
      return items.some(match)
    } else if (await this.hasProp('first')) {
      let page = null
      for (
        let pageId = await this.prop('first');
        pageId;
        pageId = await page.prop('next')
      ) {
        page = new ActivityObject(pageId)
        await page.expand()
        if (await page.hasProp('orderedItems')) {
          const orderedItems = await page.prop('orderedItems')
          if (orderedItems.some(match)) {
            return true
          }
        } else if (await page.hasProp('items')) {
          const items = await page.prop('items')
          if (items.some(match)) {
            return true
          }
        }
      }
      return false
    }
  }

  async prependData (data) {
    return await this.prepend(new ActivityObject(data))
  }

  async prepend (object) {
    await this.expand()
    const collection = await this.json()
    const objectId = await object.id()
    if (collection.orderedItems) {
      await this.patch({
        totalItems: collection.totalItems + 1,
        orderedItems: [objectId, ...collection.orderedItems]
      })
    } else if (collection.items) {
      await this.patch({
        totalItems: collection.totalItems + 1,
        items: [objectId, ...collection.items]
      })
    } else if (collection.first) {
      const first = new ActivityObject(collection.first)
      await first.expand()
      const firstJson = await first.json()
      const ip = ['orderedItems', 'items'].find((p) => p in firstJson)
      if (!ip) {
        throw new Error('No items or orderedItems in first page')
      }
      if (firstJson[ip].length < MAX_PAGE_SIZE) {
        const patch = {}
        patch[ip] = [objectId, ...firstJson[ip]]
        await first.patch(patch)
        await this.patch({ totalItems: collection.totalItems + 1 })
      } else {
        const owner = await this.owner()
        const props = {
          type: firstJson.type,
          partOf: collection.id,
          next: firstJson.id,
          attributedTo: owner
        }
        await ActivityObject.copyAddresseeProps(props, await this.json())
        props[ip] = [objectId]
        const newFirst = new ActivityObject(props)
        await newFirst.save()
        await this.patch({
          totalItems: collection.totalItems + 1,
          first: await newFirst.id()
        })
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
        await this.patch({
          totalItems: collection.totalItems - 1,
          items: collection.items
        })
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
    await this.expand()
    if (await this.hasProp('orderedItems')) {
      return await this.prop('orderedItems')
    } else if (await this.hasProp('items')) {
      return await this.prop('items')
    } else if (await this.hasProp('first')) {
      const members = []
      let ref = await this.prop('first')
      while (ref) {
        const page = new ActivityObject(ref)
        await page.expand()
        if (await page.hasProp('orderedItems')) {
          members.push(...(await page.prop('orderedItems')))
        } else if (await page.hasProp('items')) {
          members.push(...(await page.prop('items')))
        }
        ref = await page.prop('next')
      }
      return members
    }
  }

  static async empty (owner, addressees, props = {}, pageProps = {}) {
    const id = await ActivityObject.makeId('OrderedCollection')
    const page = new ActivityObject({
      type: 'OrderedCollectionPage',
      orderedItems: [],
      partOf: id,
      attributedTo: owner,
      to: addressees,
      ...pageProps
    })
    await page.save()
    const coll = new ActivityObject({
      id,
      type: 'OrderedCollection',
      totalItems: 0,
      first: await page.id(),
      last: await page.id(),
      attributedTo: owner,
      to: addressees,
      ...props
    })
    await coll.save()
    return coll
  }

  async find (test) {
    let ref = this.prop('first')
    while (ref) {
      const page = new ActivityObject(ref)
      if (!(await page.isCollectionPage())) {
        break
      }
      const items =
        (await page.prop('items')) || (await page.prop('orderedItems')) || []
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
  async save (owner = null, addressees = null) {
    const data = await this.json()
    if (!owner) {
      owner = ActivityObject.guessOwner(data)
    }
    if (!addressees) {
      addressees = ActivityObject.guessAddressees(data)
    }
    const dataId = await this.id()
    const ownerId = (await toId(owner)) || dataId
    const addresseeIds = await Promise.all(
      addressees.map((addressee) => toId(addressee))
    )
    await db.run('INSERT INTO object (id, owner, data) VALUES (?, ?, ?)', [
      await dataId,
      ownerId,
      JSON.stringify(data)
    ])
    await Promise.all(
      addresseeIds.map((addresseeId) =>
        db.run('INSERT INTO addressee (objectId, addresseeId) VALUES (?, ?)', [
          dataId,
          addresseeId
        ])
      )
    )
  }

  async apply (remote = null, addressees = null, ...args) {
    const owner = args[0]
    const ownerObj = await ActivityObject.get(owner, [
      'id',
      'type',
      'followers',
      'following',
      'pendingFollowers',
      'pendingFollowing'
    ])
    if (!remote) {
      remote = await ActivityObject.get(
        await this.prop('actor'),
        ['id'],
        ownerObj
      )
    }
    if (!addressees) {
      addressees = ActivityObject.guessAddressees(await this.json())
    }

    const remoteObj = await ActivityObject.get(remote, ['id'], ownerObj)
    const remoteAppliers = {
      Follow: async () => {
        const object = await ActivityObject.get(
          await this.prop('object'),
          ['id', 'type'],
          ownerObj
        )
        if ((await object.id()) === (await ownerObj.id())) {
          const followers = await Collection.get(
            await ownerObj.prop('followers'),
            ['id', ['orderedItems', 'items', 'first']],
            ownerObj
          )
          if (await followers.hasMember(remote)) {
            throw new Error('Already a follower')
          }
          const pendingFollowers = await Collection.get(
            await ownerObj.prop('pendingFollowers'),
            ['id', 'type', ['orderedItems', 'items', 'first']],
            ownerObj
          )
          if (await pendingFollowers.hasMember(await this.id())) {
            throw new Error('Already pending')
          }
          logger.debug(`Adding ${await this.id()} to pendingFollowers`)
          await pendingFollowers.prepend(this)
          logger.debug(
            `Pending followers now ${await pendingFollowers.prop('totalItems')}`
          )
        }
      },
      Create: async () => {
        if (await this.prop('object')) {
          const ao = new ActivityObject(await this.prop('object'))
          const owner = await ao.owner()
          if (owner && (await owner.id()) !== (await remoteObj.id())) {
            throw new Error('Cannot create something you do not own!')
          }
          await ao.cache(await remoteObj.id(), addressees)
          if (await ao.prop('inReplyTo')) {
            const inReplyTo = new ActivityObject(await ao.prop('inReplyTo'))
            await inReplyTo.expand()
            const inReplyToOwner = await inReplyTo.owner()
            if (
              inReplyToOwner &&
              (await inReplyToOwner.id()) === (await ownerObj.id())
            ) {
              if (!(await inReplyTo.canRead(await remoteObj.id()))) {
                throw new Error('Cannot reply to something you cannot read!')
              }
              const replies = new Collection(await inReplyTo.prop('replies'))
              if (!(await replies.hasMember(ao))) {
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
          if (aoOwner && (await aoOwner.id()) !== (await remoteObj.id())) {
            throw new Error('Cannot update something you do not own!')
          }
          await ao.cache(remote, addressees)
          if (await ao.prop('inReplyTo')) {
            const inReplyTo = new ActivityObject(await ao.prop('inReplyTo'))
            await inReplyTo.expand()
            const inReplyToOwner = await inReplyTo.owner()
            if (
              inReplyToOwner &&
              (await inReplyToOwner.id()) === (await ownerObj.id())
            ) {
              if (!(await inReplyTo.canRead(remote))) {
                throw new Error('Cannot reply to something you cannot read!')
              }
              const replies = new Collection(await inReplyTo.prop('replies'))
              if (!(await replies.hasMember(ao))) {
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
          if (aoOwner && (await aoOwner.id()) !== (await remoteObj.id())) {
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
            if (!(await ao.canRead(await remoteObj.id()))) {
              throw new Error('Cannot like something you cannot read!')
            }
            await ao.expand()
            const likes = new Collection(await ao.prop('likes'))
            if (!(await likes.hasMember(this))) {
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
            if (!(await ao.canRead(await remoteObj.id()))) {
              throw new Error('Cannot share something you cannot read!')
            }
            await ao.expand()
            const shares = new Collection(await ao.prop('shares'))
            if (!(await shares.hasMember(this))) {
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
            if (!(await ao.canRead(await remoteObj.id()))) {
              throw new Error('Cannot add something you cannot read!')
            }
          }
          if (await this.prop('target')) {
            const target = new ActivityObject(await this.prop('target'))
            const targetOwner = await target.owner()
            if (await User.isUser(targetOwner)) {
              if (!(await target.canRead(await remoteObj.id()))) {
                throw new Error('Cannot add to something you cannot read!')
              }
              if (!(await target.canWrite(await remoteObj.id()))) {
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
            if (!(await ao.canRead(await remoteObj.id()))) {
              throw new Error('Cannot add something you cannot read!')
            }
          }
          const targetProp =
            (await this.prop('target')) || (await this.prop('origin'))
          if (targetProp) {
            const target = new ActivityObject(targetProp)
            const targetOwner = await target.owner()
            if (await User.isUser(targetOwner)) {
              if (!(await target.canRead(await remoteObj.id()))) {
                throw new Error('Cannot remove from you cannot read!')
              }
              if (!(await target.canWrite(await remoteObj.id()))) {
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
            if (
              (await actor.id()) === (await ownerObj.id()) &&
              (await object.id()) === (await remoteObj.id())
            ) {
              const pendingFollowing = new Collection(
                await ownerObj.prop('pendingFollowing')
              )
              if (!(await pendingFollowing.hasMember(await accepted.id()))) {
                throw new Error('Not pending!')
              }
              const following = new Collection(
                await ownerObj.prop('following')
              )
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
            if (
              (await actor.id()) === (await ownerObj.id()) &&
              (await object.id()) === (await remoteObj.id())
            ) {
              const pendingFollowing = new Collection(
                await ownerObj.prop('pendingFollowing')
              )
              if (!(await pendingFollowing.hasMember(await rejected.id()))) {
                throw new Error('Not pending!')
              }
              const following = new Collection(
                await ownerObj.prop('following')
              )
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
        const undone = new ActivityObject(objectProp)
        // Make sure it's expanded
        await undone.expand()
        const actorProp = await undone.prop('actor')
        if (!actorProp) {
          throw new Error('No actor!')
        }
        const undoneActor = new ActivityObject(actorProp)
        if ((await remoteObj.id()) !== (await undoneActor.id())) {
          throw new Error('Not your activity to undo!')
        }
        switch (await undone.type()) {
          case 'Like': {
            const objectProp = await undone.prop('object')
            const object = new ActivityObject(objectProp)
            if (!(await object.canRead(await remoteObj.id()))) {
              throw new Error('Cannot unlike something you cannot read!')
            }
            const objectOwner = await object.owner()
            if (await User.isUser(objectOwner)) {
              await object.expand()
              const likes = new Collection(await object.prop('likes'))
              await likes.remove(undone)
            }
            break
          }
          case 'Announce': {
            const objectProp = await undone.prop('object')
            const object = new ActivityObject(objectProp)
            if (!(await object.canRead(await remoteObj.id()))) {
              throw new Error('Cannot unshare something you cannot read!')
            }
            const objectOwner = await object.owner()
            if (await User.isUser(objectOwner)) {
              await object.expand()
              const shares = new Collection(await object.prop('shares'))
              await shares.remove(undone)
            }
            break
          }
          case 'Follow': {
            const objectProp = await undone.prop('object')
            const object = new ActivityObject(objectProp)
            if (!(await object.canRead(await remoteObj.id()))) {
              throw new Error('Cannot unshare something you cannot read!')
            }
            const objectOwner = await object.owner()
            if (await User.isUser(objectOwner)) {
              await object.expand()
              const followers = new Collection(await object.prop('followers'))
              await followers.remove(undoneActor)
              const pendingFollowers = new Collection(
                await object.prop('pendingFollowers')
              )
              await pendingFollowers.remove(undone)
            }
          }
        }
      }
    }

    const types = Array.isArray(await this.type())
      ? await this.type()
      : [await this.type()]

    for (const type of types) {
      if (type in remoteAppliers) {
        await remoteAppliers[type]()
        break
      }
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
    const data = {
      name: this.username,
      id: this.actorId,
      type: 'Person',
      preferredUsername: this.username,
      attributedTo: this.actorId,
      to: [PUBLIC]
    }
    const props = ['inbox', 'outbox', 'followers', 'following', 'liked']
    for (const prop of props) {
      const coll = await Collection.empty(this.actorId, [PUBLIC], {
        nameMap: { en: `${this.username}'s ${prop}` }
      })
      data[prop] = await coll.id()
    }
    const privProps = ['blocked', 'pendingFollowers', 'pendingFollowing']
    for (const prop of privProps) {
      const coll = await Collection.empty(this.actorId, [], {
        nameMap: { en: `${this.username}'s ${prop}` }
      })
      data[prop] = await coll.id()
    }
    const { publicKey, privateKey } = await newKeyPair()
    const pkey = new ActivityObject({
      type: 'Key',
      owner: this.actorId,
      to: [PUBLIC],
      publicKeyPem: publicKey
    })
    await pkey.save()
    data.publicKey = await pkey.id()
    const person = new ActivityObject(data)
    await person.save()
    const passwordHash = await bcrypt.hash(this.password, 10)
    await db.run(
      'INSERT INTO user (username, passwordHash, actorId, privateKey) VALUES (?, ?, ?, ?)',
      [this.username, passwordHash, this.actorId, privateKey]
    )
  }

  static async isUser (object) {
    if (!object) {
      return false
    }
    const id = await toId(object)
    const row = await db.get('SELECT actorId FROM user WHERE actorId = ?', [
      id
    ])
    return !!row
  }

  static async usernameExists (username) {
    const row = await db.get('SELECT username FROM user WHERE username = ?', [
      username
    ])
    return !!row
  }

  static async fromActorId (actorId) {
    const row = await db.get('SELECT * FROM user WHERE actorId = ?', [actorId])
    if (!row) {
      return null
    } else {
      return User.fromRow(row)
    }
  }

  static async fromUsername (username) {
    const row = await db.get('SELECT * FROM user WHERE username = ?', [
      username
    ])
    if (!row) {
      return null
    } else {
      return User.fromRow(row)
    }
  }

  static async fromRow (row) {
    const user = new User(row.username)
    user.actorId = row.actorId
    user.privateKey = row.privateKey
    return user
  }

  async getActor (username) {
    const actor = new ActivityObject(this.actorId)
    return actor
  }

  static async authenticate (username, password) {
    const row = await db.get('SELECT * FROM user WHERE username = ?', [
      username
    ])
    if (!row) {
      return null
    }
    if (!(await bcrypt.compare(password, row.passwordHash))) {
      return null
    }
    return User.fromRow(row)
  }

  static async updateAllKeys () {
    // TODO: change this to use a cursor
    const rows = await db.all(
      "SELECT * FROM user where privateKey LIKE '-----BEGIN RSA PRIVATE KEY-----%'"
    )
    for (const row of rows) {
      const actor = new ActivityObject(row.actorId)
      const publicKey = new ActivityObject(await actor.prop('publicKey'))
      const newPublicKeyPem = toSpki(await publicKey.prop('publicKeyPem'))
      const newPrivateKeyPem = toPkcs8(row.privateKey)
      logger.info(`Updating keys for ${row.actorId}`)
      await publicKey.patch({ publicKeyPem: newPublicKeyPem })
      await actor.patch({ publicKey: await publicKey.id() })
      await db.run('UPDATE user SET privateKey = ? WHERE actorId = ?', [
        newPrivateKeyPem,
        row.actorId
      ])
    }
  }
}

class Upload {
  constructor (buffer, mediaType) {
    this.buffer = buffer
    this.mediaType = mediaType
    const extension = mime.getExtension(mediaType) || 'bin'
    this.relative = `${nanoid()}.${extension}`
  }

  static async fromRelative (relative) {
    const row = await db.get('SELECT * FROM upload WHERE relative = ?', [
      relative
    ])
    if (!row) {
      return null
    } else {
      const upload = new Upload()
      upload.relative = row.relative
      upload.mediaType = row.mediaType
      upload.objectId = row.objectId
      return upload
    }
  }

  setObjectId (objectId) {
    this.objectId = objectId
  }

  path () {
    return path.join(UPLOAD_DIR, this.relative)
  }

  async readable () {
    try {
      await fsp.access(this.path(), fsp.constants.R_OK)
      return true
    } catch (err) {
      return false
    }
  }

  async save () {
    if (!this.objectId) {
      throw new Error('Cannot save upload without objectId')
    }
    await fsp.writeFile(this.path(), this.buffer)
    await db.run(
      'INSERT INTO upload (relative, mediaType, objectId) VALUES (?, ?, ?)',
      [this.relative, this.mediaType, this.objectId]
    )
  }
}

// Server

const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: winston.format.printf((info) => {
    return `${new Date().toISOString()} ${info.level}: ${info.message}`
  }),
  transports: [new winston.transports.Console()]
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

// Initialize Multer
const upload = multer({ storage: multer.memoryStorage() })

app.use((req, res, next) => {
  const oldEnd = res.end
  res.end = function (...args) {
    const subject = req.auth?.subject || '-'
    logger.info(`${res.statusCode} ${req.method} ${req.url} (${subject})`)
    oldEnd.apply(this, args)
  }
  next()
})

app.use(
  express.json({
    type: [
      'application/json',
      'application/activity+json',
      'application/ld+json'
    ]
  })
) // for parsing application/json
app.use(express.urlencoded({ extended: true })) // for HTML forms

// Enable session management
app.use(cookieParser())
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
)

// CSRF token middleware
const csrf = wrap(async (req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = nanoid()
  }
  next()
})

class JWTTypeError extends Error {
  constructor (type) {
    super(`Invalid JWT type ${type}`)
    this.name = 'JWTTypeError'
  }
}

class Server {
  #origin
  #publicKey
  #privateKey
  static #singleton
  constructor (origin, publicKey, privateKey) {
    this.#origin = origin
    this.#publicKey = publicKey
    this.#privateKey = privateKey
  }

  static async get () {
    if (!Server.#singleton) {
      const origin = makeUrl('')
      const row = await db.get('SELECT * FROM server where origin = ?', [
        origin
      ])
      if (!row) {
        Server.#singleton = null
      } else {
        Server.#singleton = new Server(
          row.origin,
          row.publicKey,
          row.privateKey
        )
      }
    }
    return Server.#singleton
  }

  keyId () {
    return makeUrl('key')
  }

  toJSON () {
    return {
      '@context': CONTEXT,
      id: this.#origin,
      type: 'Service',
      name: process.OPP_NAME || 'One Page Pub',
      publicKey: {
        type: 'Key',
        id: this.keyId(),
        owner: this.#origin,
        publicKeyPem: this.#publicKey
      }
    }
  }

  getKeyJSON () {
    return {
      '@context': CONTEXT,
      type: 'Key',
      id: this.keyId(),
      owner: this.#origin,
      publicKeyPem: this.#publicKey
    }
  }

  privateKey () {
    return this.#privateKey
  }

  publicKey () {
    return this.#publicKey
  }

  static async ensureKey () {
    const row = await db.get('SELECT * FROM server WHERE origin = ?', [
      makeUrl('')
    ])
    if (!row) {
      const { publicKey, privateKey } = await newKeyPair()
      await db.run(
        'INSERT INTO server (origin, privateKey, publicKey) ' +
          ' VALUES (?, ?, ?) ' +
          ' ON CONFLICT DO NOTHING',
        [makeUrl(''), privateKey, publicKey]
      )
    } else if (!row.privateKey) {
      const { publicKey, privateKey } = await newKeyPair()
      await db.run(
        'UPDATE server ' +
          ' SET privateKey = ?, publicKey = ? ' +
          ' WHERE origin = ?',
        [privateKey, publicKey, makeUrl('')]
      )
    } else if (row.privateKey.match(/^-----BEGIN RSA PRIVATE KEY-----/)) {
      const privateKey = toPkcs8(row.privateKey)
      const publicKey = toSpki(row.publicKey)
      await db.run(
        'UPDATE server ' +
          ' SET privateKey = ?, publicKey = ? ' +
          ' WHERE origin = ?',
        [privateKey, publicKey, makeUrl('')]
      )
    }
  }
}

// Check token type
const tokenTypeCheck = wrap(async (req, res, next) => {
  if (req.auth && req.auth.type && req.auth.type !== 'access') {
    throw new JWTTypeError(req.auth.type)
  } else {
    next()
  }
})

const newKeyPair = async () => {
  return await generateKeyPair('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    },
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    }
  })
}

app.use(passport.initialize()) // Initialize Passport
app.use(passport.session())

app.use(
  wrap(async (req, res, next) => {
    const server = await Server.get()
    req.jwtKeyData = server.privateKey()
    return next()
  })
)

async function jwtOptional (req, res, next) {
  const mw = expressjwt({
    credentialsRequired: false,
    secret: req.jwtKeyData,
    algorithms: ['RS256']
  })
  return mw(req, res, next)
}

async function jwtRequired (req, res, next) {
  const mw = expressjwt({
    credentialsRequired: true,
    secret: req.jwtKeyData,
    algorithms: ['RS256']
  })
  return mw(req, res, next)
}

passport.use(
  new LocalStrategy(function (username, password, done) {
    (async () => {
      const user = await User.authenticate(username, password)
      if (!user) {
        return done(null, false, {
          message: 'Incorrect username or password.'
        })
      } else {
        return done(null, user)
      }
    })()
  })
)

passport.serializeUser(function (user, done) {
  const results = user.username
  done(null, results)
})

passport.deserializeUser(function (username, done) {
  (async () => {
    try {
      const user = await User.fromUsername(username)
      done(null, user)
    } catch (err) {
      done(err)
    }
  })()
})

app.use('/bootstrap/', express.static('node_modules/bootstrap/dist/'))
app.use('/popper/', express.static('node_modules/@popperjs/core/dist/umd'))

const cors = (req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*')
  next()
}

app.get(
  '/',
  cors,
  wrap(async (req, res) => {
    if (req.accepts('html')) {
      res.send(
        page(
          'Home',
          `
    <p>This is an <a href="https://www.w3.org/TR/activitypub/">ActivityPub</a> server.</p>
    <p>It is currently in development.</p>
`,
          req.user
        )
      )
    } else if (
      req.accepts('json') ||
      req.accepts('application/activity+json') ||
      req.accepts('application/ld+json')
    ) {
      const server = await Server.get()
      res.set('Content-Type', 'application/activity+json')
      res.json(await server.toJSON())
    } else {
      res.status(406).send('Not Acceptable')
    }
  })
)

app.get(
  '/key',
  cors,
  wrap(async (req, res) => {
    const server = await Server.get()
    res.set('Content-Type', 'application/activity+json')
    res.json(await server.getKeyJSON())
  })
)

const page = (title, body, user = null) => {
  const version = process.env.npm_package_version
  return `
  <!DOCTYPE html>
  <html>
    <head>
      <title>${title} - ${NAME}</title>
      <link rel="stylesheet" href="/bootstrap/css/bootstrap.min.css">
      <style>
      .outer {
        margin-bottom: 100px; /* Margin bottom by footer height */
      }
      .footer {
        position: absolute;
        bottom: 0;
        width: 100%;
        background-color: "light grey"; /* Footer background color */
        padding: 10px 0;
      }
      </style>
    </head>
    <body>

      <div class="container mx-auto outer" style="max-width: 600px;">
        <nav class="navbar navbar-expand-lg navbar-light bg-light">
          <a class="navbar-brand" href="/">${NAME}</a>
          <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
          </button>
          <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav">
              <li class="nav-item active">
                <a class="nav-link" href="/">Home</a>
              </li>
              ${
                user
                  ? `
                <li class="nav-item active">
                  <form action="/logout" method="POST" class="form-inline my-2 my-lg-0">
                  <button type="submit" class="btn btn-link nav-link">Logout</button>
                  </form>
                </li>
                `
                  : `
                <li class="nav-item active">
                  <a class="nav-link" href="/register">Register</a>
                </li>
                <li class="nav-item active">
                  <a class="nav-link" href="/login">Log in</a>
                </li>
              `
              }
            </ul>
          </div>
        </nav>

        <div class="container">
          <div class="row">
            <div class="col">
              <h1>${title}</h1>
              ${body}
            </div>
          </div>
        </div>

        <div class="footer bg-light" style="max-width: 600px;">
          <div class="container text-center">
          <p>
            One Page Pub ${
              version ? `<span class="version">${version}</span>` : ''
            }
            | <a href="https://github.com/evanp/onepage.pub" target="_blank">GitHub</a></p>
          </div>
        </div>
      </div>

      <script src="/popper/popper.min.js"></script>
      <script src="/bootstrap/js/bootstrap.min.js"></script>
    </body>
  </html>`
}

app.get(
  '/queue',
  cors,
  wrap(async (req, res) => {
    res.status(200)
    res.type('json')
    res.json(pq.count)
  })
)

app.get(
  '/register',
  csrf,
  wrap(async (req, res) => {
    res.type('html')
    res.status(200)
    res.end(
      page(
        'Register',
        `
    <div class="container mx-auto" style="max-width: 600px;">
    <form method="POST" action="/register">
      ${
        !INVITE_CODE || INVITE_CODE.length === 0
          ? ''
          : `<div class="form-group row mb-3">
        <label for="invitecode" class="col-sm-4 col-form-label text-right">Invite code</label>
        <div class="col-sm-8">
        <input type="text" name="invitecode" id="invitecode" class="form-control" placeholder="Invite code" />
        </div>
      </div>`
      }
      <div class="form-group row mb-3">
        <label for="username" class="col-sm-4 col-form-label text-right">Username</label>
        <div class="col-sm-8">
        <input type="text" name="username" id="username" class="form-control" placeholder="Username" />
        </div>
      </div>
      <div class="form-group row mb-3">
        <label for="password" class="col-sm-4 col-form-label text-right">Password</label>
        <div class="col-sm-8">
          <input type="password" class="form-control" name="password" id="password">
        </div>
      </div>
      <div class="form-group row mb-3">
        <label for="confirmation" class="col-sm-4 col-form-label text-right">Confirm</label>
        <div class="col-sm-8">
          <input type="password" class="form-control" name="confirmation" id="confirmation">
        </div>
      </div>
      <div class="form-group row">
       <div class="col-sm-4"></div> <!-- Empty space equivalent to label width -->
       <div class="col-sm-8">
        <button type="submit" class="btn btn-primary">Register</button>
        <a href='/' class="btn btn-secondary">Cancel</a>
        </div>
      </div>
    </form>
  </div>`
      )
    )
  })
)

app.post(
  '/register',
  csrf,
  wrap(async (req, res) => {
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
    if (
      INVITE_CODE &&
      INVITE_CODE.length > 0 &&
      (!req.body.invitecode || req.body.invitecode !== INVITE_CODE)
    ) {
      throw new createError.BadRequest('Correct invite code required')
    }
    const username = req.body.username

    if (await User.usernameExists(username)) {
      throw new createError.BadRequest('Username already exists')
    }

    const password = req.body.password
    const user = new User(username, password)
    await user.save()
    const token = await jwtsign(
      {
        jwtid: nanoid(),
        type: 'access',
        subject: user.actorId,
        scope: 'read write',
        issuer: makeUrl('')
      },
      req.jwtKeyData,
      { algorithm: 'RS256' }
    )

    req.login(user, (err) => {
      if (err) {
        throw new createError.InternalServerError('Failed to login')
      }
      res.type('html')
      res.status(200)
      res.end(
        page(
          'Registered',
          `
      <p>Registered <a class="actor" href="${user.actorId}">${username}</a></p>
      <p>Personal access token is <span class="token">${token}</span>`,
          user
        )
      )
    })
  })
)

app.get(
  '/login',
  csrf,
  wrap(async (req, res) => {
    res.type('html')
    res.status(200)
    res.end(
      page(
        'Log in',
        `
    <div class="container mx-auto" style="max-width: 600px;">
    <form method="POST" action="/login">
    <div class="form-group row mb-3">
      <label for="username" class="col-sm-4 col-form-label text-right">Username</label>
      <div class="col-sm-8">
        <input type="text" name="username" id="username" class="form-control" placeholder="Username" />
      </div>
    </div>
    <div class="form-group row mb-3">
      <label for="password" class="col-sm-4 col-form-label text-right">Password</label>
      <div class="col-sm-8">
        <input type="password" class="form-control" name="password" id="password">
      </div>
    </div>
    <div class="form-group row">
       <div class="col-sm-4"></div> <!-- Empty space equivalent to label width -->
       <div class="col-sm-8">
        <button type="submit" class="btn btn-primary">Login</button>
        <a href='/' class="btn btn-secondary">Cancel</a>
      </div>
    </div>
    </form>`
      )
    )
  })
)

app.post('/login', (req, res, next) => {
  const redirectTo = req.session.redirectTo
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      res.redirect('/login?error=1')
      return
    }
    if (!user) {
      res.redirect('/login')
      return
    }
    req.login(user, (err) => {
      if (err) {
        next(err)
        return
      }
      if (redirectTo) {
        res.redirect(redirectTo)
      } else {
        res.redirect('/login/success')
      }
    })
  })(req, res, next)
})

app.get(
  '/login/success',
  passport.authenticate('session'),
  wrap(async (req, res) => {
    if (!req.isAuthenticated()) {
      throw new createError.InternalServerError('Not authenticated')
    }
    const user = req.user
    if (!user) {
      throw new createError.InternalServerError(
        'Invalid user even though isAuthenticated() is true'
      )
    }

    const token = await jwtsign(
      {
        jwtid: nanoid(),
        type: 'access',
        subject: user.actorId,
        scope: 'read write',
        issuer: makeUrl('')
      },
      req.jwtKeyData,
      { algorithm: 'RS256' }
    )

    res.type('html')
    res.status(200)
    res.end(
      page(
        'Logged in',
        `
    <p>Logged in <a class="actor" href="${user.actorId}">${user.username}</a></p>
    <p>Personal access token is <span class="token">${token}</span>`,
        user
      )
    )
  })
)

app.post(
  '/logout',
  wrap(async (req, res) => {
    req.logout((err) => {
      if (err) {
        throw new createError.InternalServerError('Failed to logout')
      } else {
        res.redirect('/')
      }
    })
  })
)

app.get(
  '/live',
  wrap(async (req, res) => {
    res.status(200)
    res.set('Content-Type', 'text/plain')
    res.end('OK')
  })
)

app.get(
  '/ready',
  wrap(async (req, res) => {
    const dbReady = await db.ready()
    if (!dbReady) {
      throw new createError.InternalServerError('Database not ready')
    }
    res.status(200)
    res.set('Content-Type', 'text/plain')
    res.end('OK')
  })
)

app.get(
  '/.well-known/webfinger',
  cors,
  wrap(async (req, res) => {
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
    const user = await db.get(
      'SELECT username, actorId FROM user WHERE username = ?',
      [username]
    )
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
  })
)

app.post(
  '/endpoint/proxyUrl',
  jwtRequired,
  tokenTypeCheck,
  wrap(async (req, res) => {
    const id = req.body.id
    if (!id) {
      throw new createError.BadRequest('Missing id')
    }
    const user = await User.fromActorId(req.auth?.subject)
    if (!user) {
      throw new createError.InternalServerError('Invalid user')
    }
    if (!req.auth.scope || !req.auth.scope.split(' ').includes('read')) {
      throw new createError.Unauthorized('Missing read scope')
    }
    const actor = await user.getActor()
    const publicKey = new ActivityObject(await actor.prop('publicKey'))
    const date = new Date().toUTCString()
    const signature = new HTTPSignature(
      await publicKey.id(),
      user.privateKey,
      'GET',
      id,
      date
    )
    const fetchRes = await fetch(id, {
      headers: {
        Accept:
          'application/activity+json;q=1,application/ld+json;q=0.5,application/json;q=0.1',
        Signature: signature.header,
        Date: date
      }
    })
    if (![200, 410].includes(fetchRes.status)) {
      logger.warn(`Error fetching ${id}: ${fetchRes.status}`)
      throw new createError.InternalServerError('Error fetching object')
    }
    const fetchJson = await fetchRes.json()
    if (fetchRes.status === 410 && fetchJson.type !== 'Tombstone') {
      logger.warn(
        `Error fetching ${id}: status = 410 but type is '${fetchJson.type}', not Tombstone`
      )
      throw new createError.InternalServerError('Error fetching object')
    }
    res.status(fetchRes.status)
    res.set('Content-Type', 'application/activity+json')
    res.json(fetchJson)
  })
)

app.get(
  '/endpoint/oauth/authorize',
  cors,
  csrf,
  passport.authenticate('session'),
  wrap(async (req, res) => {
    if (!req.isAuthenticated()) {
      req.session.redirectTo = req.originalUrl
      res.redirect('/login')
    } else {
      if (!req.query.client_id) {
        throw new createError.BadRequest('Missing client_id')
      }
      let clientIdUrl = null
      let client = null
      try {
        clientIdUrl = new URL(req.query.client_id)
      } catch {
        throw new createError.BadRequest('Invalid client_id')
      }
      if (clientIdUrl.protocol !== 'https:') {
        throw new createError.BadRequest('Invalid client_id')
      }
      try {
        client = await ActivityObject.getFromRemote(req.query.client_id)
      } catch (err) {
        throw new createError.BadRequest('Invalid client_id')
      }
      if (!req.query.redirect_uri) {
        throw new createError.BadRequest('Missing redirect_uri')
      }
      if (req.query.redirect_uri !== (await client.prop('redirectURI'))) {
        throw new createError.BadRequest('Invalid redirect_uri')
      }
      if (!req.query.response_type || req.query.response_type !== 'code') {
        throw new createError.BadRequest('Missing or invalid response_type')
      }
      if (!req.query.scope) {
        throw new createError.BadRequest('Missing scope')
      }
      if (!req.query.code_challenge) {
        throw new createError.BadRequest('Missing code_challenge')
      }
      if (
        !req.query.code_challenge_method ||
        req.query.code_challenge_method !== 'S256'
      ) {
        throw new createError.BadRequest('Unsupported code challenge value')
      }

      const name = await client.prop('name')
      const url = await client.prop('url')
      const icon = (await client.prop('icon'))
        ? (await client.prop('icon').href) || (await client.prop('icon').url)
        : null
      const description =
        (await client.prop('summary')) || (await client.prop('summaryMap')?.en)
      const author = await client.prop('attributedTo')?.name
      const authorUrl = await client.prop('attributedTo')?.url

      res.type('html')
      res.status(200)
      res.end(
        page(
          'Authorize',
          `
      <p>
        This app is asking to authorize access to your account.
        <ul>
          <li>Client ID: ${req.query.client_id}</li>
          <li>Name: ${
            name
              ? url
                ? `<a target="_blank" href="${url}">${name}</a>`
                : name
              : 'N/A'
          }</li>
          <li>Icon: ${icon ? `<img src="${icon}" >` : 'N/A'}</li>
          <li>Description: ${description || 'N/A'}</li>
          <li>Author: ${
            author
              ? authorUrl
                ? `<a target="_blank" href="${authorUrl}">${author}</a>`
                : author
              : 'N/A'
          }</li>
          <li>Scope: ${req.query.scope}</li>
        </ul>
      </p>
      <form method="POST" action="/endpoint/oauth/authorize">
      <input type="hidden" name="csrf_token" value="${req.session.csrfToken}" />
      <input type="hidden" name="client_id" value="${req.query.client_id}" />
      <input type="hidden" name="redirect_uri" value="${
        req.query.redirect_uri
      }" />
      <input type="hidden" name="scope" value="${req.query.scope}" />
      <input type="hidden" name="code_challenge" value="${
        req.query.code_challenge
      }" />
      <input type="hidden" name="state" value="${req.query.state}" />
      <input type="submit" value="Authorize" />
      </form>`,
          req.user
        )
      )
    }
  })
)

app.post(
  '/endpoint/oauth/authorize',
  csrf,
  passport.authenticate('session'),
  wrap(async (req, res) => {
    if (!req.isAuthenticated()) {
      res.redirect('/login&returnTo=' + encodeURIComponent(req.originalUrl))
    } else {
      if (
        !req.body.csrf_token ||
        req.body.csrf_token !== req.session.csrfToken
      ) {
        throw new createError.BadRequest('Invalid CSRF token')
      }
      if (!req.body.client_id) {
        throw new createError.BadRequest('Missing client_id')
      }
      if (!req.body.redirect_uri) {
        throw new createError.BadRequest('Missing redirect_uri')
      }
      if (!req.body.scope) {
        throw new createError.BadRequest('Missing scope')
      }
      if (!req.body.code_challenge) {
        throw new createError.BadRequest('Missing code_challenge')
      }
      // We use a JWT for the authorization code
      const code = await jwtsign(
        {
          jwtid: nanoid(),
          type: 'authz',
          subject: req.user.actorId,
          scope: req.body.scope,
          challenge: req.body.code_challenge,
          client: req.body.client_id,
          redir: req.body.redirect_uri,
          expiresIn: '10m',
          issuer: makeUrl('')
        },
        req.jwtKeyData,
        { algorithm: 'RS256' }
      )
      const state = req.body.state
      const location =
        req.body.redirect_uri + '?' + querystring.stringify({ code, state })
      res.redirect(location)
    }
  })
)

app.post(
  '/endpoint/oauth/token',
  cors,
  wrap(async (req, res) => {
    const contentTypeHeader = req.get('Content-Type')
    if (!contentTypeHeader) {
      throw new createError.BadRequest('Invalid Content-Type')
    }
    const mediaType = contentTypeHeader.split(';')[0].trim()
    if (mediaType !== 'application/x-www-form-urlencoded') {
      throw new createError.BadRequest('Invalid Content-Type')
    }
    if (
      !req.body.grant_type ||
      !['authorization_code', 'refresh_token'].includes(req.body.grant_type)
    ) {
      throw new createError.BadRequest('Invalid grant_type')
    }
    if (req.body.grant_type === 'authorization_code') {
      if (!req.body.code) {
        throw new createError.BadRequest('Missing code')
      }
      if (!req.body.redirect_uri) {
        throw new createError.BadRequest('Missing redirect_uri')
      }
      if (!req.body.client_id) {
        throw new createError.BadRequest('Missing client_id')
      }
      if (!req.body.code_verifier) {
        throw new createError.BadRequest('Missing code_verifier')
      }
      const code = req.body.code
      const fields = await jwtverify(code, req.jwtKeyData, {
        algorithm: 'RS256'
      })
      if (fields.type !== 'authz') {
        throw new createError.BadRequest('Invalid code')
      }
      if (fields.client !== req.body.client_id) {
        throw new createError.BadRequest('Invalid client')
      }
      if (fields.redir !== req.body.redirect_uri) {
        throw new createError.BadRequest('Invalid redirect_uri')
      }
      if (
        fields.challenge !==
        (await base64URLEncode(
          crypto.createHash('sha256').update(req.body.code_verifier).digest()
        ))
      ) {
        throw new createError.BadRequest('Invalid code_verifier')
      }
      if (fields.issuer !== makeUrl('')) {
        throw new createError.BadRequest('Invalid issuer')
      }
      const user = User.fromActorId(fields.subject)
      if (!user) {
        throw new createError.BadRequest('Invalid user')
      }
      // TODO: check that jwtid has not be reused
      const token = await jwtsign(
        {
          jwtid: nanoid(),
          type: 'access',
          subject: fields.subject,
          scope: fields.scope,
          client: fields.client,
          expiresIn: '1d',
          issuer: makeUrl('')
        },
        req.jwtKeyData,
        { algorithm: 'RS256' }
      )
      const refreshToken = await jwtsign(
        {
          jwtid: nanoid(),
          type: 'refresh',
          subject: fields.subject,
          scope: fields.scope,
          client: fields.client,
          expiresIn: '30d',
          issuer: makeUrl('')
        },
        req.jwtKeyData,
        { algorithm: 'RS256' }
      )
      res.set('Content-Type', 'application/json')
      res.json({
        access_token: token,
        token_type: 'Bearer',
        scope: fields.scope,
        expires_in: 86400,
        refresh_token: refreshToken
      })
    } else if (req.body.grant_type === 'refresh_token') {
      if (!req.body.refresh_token) {
        throw new createError.BadRequest('Missing refresh_token')
      }
      const refreshToken = req.body.refresh_token
      const fields = await jwtverify(refreshToken, req.jwtKeyData, {
        algorithm: 'RS256'
      })
      if (fields.type !== 'refresh') {
        throw new createError.BadRequest('Invalid code')
      }
      if (fields.issuer !== makeUrl('')) {
        throw new createError.BadRequest('Invalid issuer')
      }
      const user = User.fromActorId(fields.subject)
      if (!(await user)) {
        throw new createError.BadRequest('Invalid user')
      }
      const token = await jwtsign(
        {
          jwtid: nanoid(),
          type: 'access',
          subject: fields.subject,
          scope: fields.scope,
          client: fields.client,
          expiresIn: '1d',
          issuer: makeUrl('')
        },
        req.jwtKeyData,
        { algorithm: 'RS256' }
      )
      const newRefreshToken = await jwtsign(
        {
          jwtid: nanoid(),
          type: 'refresh',
          subject: fields.subject,
          scope: fields.scope,
          client: fields.client,
          expiresIn: '30d',
          issuer: makeUrl('')
        },
        req.jwtKeyData,
        { algorithm: 'RS256' }
      )
      res.set('Content-Type', 'application/json')
      res.json({
        access_token: token,
        token_type: 'Bearer',
        scope: fields.scope,
        expires_in: 86400,
        refresh_token: newRefreshToken
      })
    }
  })
)

app.post(
  '/endpoint/upload',
  jwtRequired,
  tokenTypeCheck,
  upload.fields([
    { name: 'file', maxCount: 1 },
    { name: 'object', maxCount: 1 }
  ]),
  wrap(async (req, res) => {
    if (!req.files || !req.files.file || !req.files.file[0]) {
      throw new createError.BadRequest('Missing file')
    }
    if (!req.files || !req.files.object || !req.files.object[0]) {
      throw new createError.BadRequest('Missing object')
    }

    const uploaded = new Upload(
      req.files.file[0].buffer,
      req.files.file[0].mimetype,
      req.files.file[0].originalname
    )

    if (!req.auth?.subject) {
      throw new createError.Unauthorized('Missing subject')
    }

    const owner = new ActivityObject(req.auth.subject)

    const ownerId = await owner.id()

    const jsonBuffer = req.files.object[0].buffer
    let data = JSON.parse(jsonBuffer.toString('utf8'))

    // We do some testing for implicit create
    const type = data.type
    if (ActivityObject.isActivityType(type)) {
      // all good
    } else if (ActivityObject.isObjectType(type)) {
      data = { type: 'Create', object: data }
    } else if (Activity.duckType(data)) {
      data.type = Array.isArray(data.type)
        ? data.type.concat('Activity')
        : data.type
          ? [data.type, 'Activity']
          : 'Activity'
    } else {
      data.type = Array.isArray(data.type)
        ? data.type.concat('Object')
        : data.type
          ? [data.type, 'Object']
          : 'Object'
      data = { type: 'Create', object: data }
    }

    data.id = await ActivityObject.makeId(data.type)
    data.actor = ownerId
    if (data.object) {
      data.object.url = makeUrl(`/uploads/${uploaded.relative}`)
      data.object.mediaType = uploaded.mediaType
    }

    const activity = new Activity(data)

    activity.setActor(ownerId)

    await activity.apply()
    await activity.save()

    uploaded.setObjectId(await toId(await activity.prop('object')))
    await uploaded.save()

    const outbox = new Collection(await owner.prop('outbox'))
    await outbox.prepend(activity)
    const inbox = new Collection(await owner.prop('inbox'))
    await inbox.prepend(activity)
    pq.add(activity.distribute())
    const output = await activity.expanded()
    output['@context'] = output['@context'] || CONTEXT
    res.status(201)
    res.set('Content-Type', 'application/activity+json')
    res.set('Location', await activity.id())
    res.json(output)
  })
)

app.get(
  '/uploads/*',
  jwtOptional,
  tokenTypeCheck,
  cors,
  HTTPSignature.authenticate,
  wrap(async (req, res) => {
    const relative = req.params[0]
    const uploaded = await Upload.fromRelative(relative)
    if (!uploaded || !uploaded.relative) {
      throw new createError.NotFound('Upload record not found')
    }
    if (!(await uploaded.readable())) {
      throw new createError.NotFound('File not found')
    }
    const obj = new ActivityObject(uploaded.objectId)
    if (!obj) {
      throw new createError.NotFound('Object not found')
    }
    if (!(await obj.canRead(req.auth?.subject))) {
      if (req.auth?.subject) {
        throw new createError.Forbidden('Not authorized to read this object')
      } else {
        throw new createError.Unauthorized(
          `You must provide credentials to read ${relative}`
        )
      }
    }
    res.status(200)
    res.set('Content-Type', await obj.prop('mediaType'))
    res.sendFile(uploaded.path())
  })
)

app.get(
  '/:type/:id',
  jwtOptional,
  tokenTypeCheck,
  cors,
  HTTPSignature.authenticate,
  wrap(async (req, res) => {
    const full = makeUrl(req.originalUrl)
    if (
      req.auth &&
      req.auth.scope &&
      !req.auth.scope.split(' ').includes('read')
    ) {
      throw new createError.Forbidden('Missing read scope')
    }
    const obj = await ActivityObject.getById(full)
    if (!obj) {
      throw new createError.NotFound('Object not found')
    }
    if (!(await obj.canRead(req.auth?.subject))) {
      if (req.auth?.subject) {
        throw new createError.Forbidden('Not authorized to read this object')
      } else {
        throw new createError.Unauthorized(
          `You must provide credentials to read ${full}`
        )
      }
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
      // XXX: Mastodon only accepts URLs here :(

      const urlProps = ['inbox', 'outbox', 'followers', 'following', 'liked']

      for (const prop of urlProps) {
        if (output[prop]) {
          output[prop] = await toId(output[prop])
        }
      }

      // Add a webfinger for users
      const username = await obj.prop('preferredUsername')
      if (username) {
        const hostPart = new URL(ORIGIN).host
        output.webfinger = `${username}@${hostPart}`
      }
    }
    if (output.type === 'Tombstone') {
      res.status(410)
    }
    output['@context'] = output['@context'] || CONTEXT
    res.set('Content-Type', 'application/activity+json')
    res.json(output)
  })
)

app.post(
  '/:type/:id',
  jwtOptional,
  tokenTypeCheck,
  HTTPSignature.authenticate,
  wrap(async (req, res) => {
    const full = makeUrl(req.originalUrl)
    const obj = new ActivityObject(full)
    if (!obj) {
      throw new createError.NotFound('Object not found')
    }
    const owner = await obj.owner()
    if (!(await obj.json())) {
      throw new createError.InternalServerError('Invalid object')
    }
    if (!owner) {
      throw new createError.InternalServerError('No owner found for object')
    }
    if (full === (await owner.prop('outbox'))) {
      if (req.auth?.subject !== (await owner.id())) {
        throw new createError.Forbidden('You cannot post to this outbox')
      }
      if (!req.auth?.scope || !req.auth?.scope.split(' ').includes('write')) {
        throw new createError.Forbidden(
          'This app does not have permission to write to this outbox'
        )
      }
      const ownerId = await owner.id()
      const outbox = await Collection.fromActivityObject(obj)
      let data = req.body
      // We do some testing for implicit create
      const type = data.type
      if (ActivityObject.isActivityType(type)) {
        // all good
      } else if (ActivityObject.isObjectType(type)) {
        data = { type: 'Create', object: data }
      } else if (Activity.duckType(data)) {
        data.type = Array.isArray(data.type)
          ? data.type.concat('Activity')
          : data.type
            ? [data.type, 'Activity']
            : 'Activity'
      } else {
        data.type = Array.isArray(data.type)
          ? data.type.concat('Object')
          : data.type
            ? [data.type, 'Object']
            : 'Object'
        data = { type: 'Create', object: data }
      }
      data.id = await ActivityObject.makeId(data.type)
      data.actor = ownerId
      const activity = new Activity(data, ownerId)
      await activity.apply()
      await activity.save()
      await outbox.prepend(activity)
      const inbox = new Collection(await owner.prop('inbox'))
      await inbox.prepend(activity)
      pq.add(activity.distribute())
      const output = {
        '@context': CONTEXT,
        ...(await activity.expanded())
      }
      res.status(201)
      res.set('Content-Type', 'application/activity+json')
      res.set('Location', await activity.id())
      res.json(output)
    } else if (full === (await owner.prop('inbox'))) {
      // remote delivery
      if (!req.auth?.subject) {
        throw new createError.Unauthorized('Invalid HTTP signature')
      }
      const remote = await ActivityObject.getById(req.auth.subject, owner)
      const remoteId = await remote.id()
      if (!(typeof remoteId === 'string')) {
        throw new createError.InternalServerError(
          `Invalid remote id ${JSON.stringify(remoteId)}`
        )
      }
      if (domainIsBlocked(remoteId)) {
        throw new createError.Forbidden('Remote delivery blocked')
      }
      if (await User.isUser(remote)) {
        throw new createError.Forbidden('Remote delivery only')
      }
      const activity = new RemoteActivity(req.body)
      const actor =
        (await activity.prop('actor')) || (await activity.prop('attributedTo'))
      if (actor) {
        const actorId = await toId(actor)
        logger.debug(`New remote activity from ${actor}`)
        if (actorId !== remoteId) {
          logger.debug(`Actor ${actorId} does not match remote ${remoteId}`)
          throw new createError.Forbidden(
            `Actor ${actorId} does not match remote ${remoteId}`
          )
        }
      } else {
        activity.setActor(remote)
      }
      await activity.apply(null, null, await owner.json())
      await activity.save(remote)
      // Since it was delivered here, owner is an implicit addressee
      await activity.ensureAddressee(owner)
      const inbox = new Collection(await owner.prop('inbox'))
      await inbox.prepend(activity)
      res.status(202)
      res.set('Content-Type', 'application/activity+json')
      res.json(req.body)
    } else {
      throw new createError.MethodNotAllowed('You cannot POST to this object')
    }
  })
)

app.use((err, req, res, next) => {
  if (createError.isHttpError(err)) {
    if (err.statusCode > 500) {
      logger.error(`Error status ${err.statusCode}: `, err)
      logger.debug(err.stack)
    }
    res.status(err.statusCode)
    if (res.expose) {
      res.json({ message: err.message })
    } else {
      res.json({ message: err.message })
    }
  } else if (err.name === 'UnauthorizedError') {
    res.set('Content-Type', 'application/json')
    res.status(401)
    res.json({ error_description: err.message, error: 'invalid_token' })
  } else if (err.name === 'JWTTypeError') {
    res.set('Content-Type', 'application/json')
    res.status(401)
    res.json({ error_description: err.message, error: 'invalid_token' })
  } else {
    logger.error('Error status 500: ', err)
    logger.debug(err.stack)
    res.status(500)
    res.json({ message: err.message })
  }
})

process.on('unhandledRejection', (err) => {
  logger.error('Unhandled rejection: ', err)
  logger.debug(err.stack)
})

process.on('uncaughtException', (err) => {
  logger.error('Uncaught exception: ', err)
  logger.debug(err.stack)
})

// Define a function for cleanup tasks
const cleanup = () => {
  logger.info(`Closing server on ${PORT}`)
  server.close(() => {
    logger.info(`Server on ${PORT} is closed`)
    logger.info(`Closing database on ${PORT}`)
    db.close().then(() => {
      logger.info(`Closed database on ${PORT}`)
      logger.info(`Closing logger on ${PORT}`)
      logger.close()
      process.exit(0)
    })
  })
}

// Listen for SIGINT (Ctrl+C) and SIGTERM (Termination) signals

process.on('SIGINT', () => {
  logger.info(`Closing app on SIGINT on ${PORT}`)
  cleanup()
})

process.on('SIGTERM', () => {
  logger.info(`Closing app on SIGTERM on ${PORT}`)
  cleanup()
})

process.on('exit', (code) => {
  console.log(`About to exit with code: ${code}`)
})

// If we're public, run with ORIGIN. Otherwise,
// run with HTTPS

const server = process.env.OPP_ORIGIN
  ? http.createServer(app)
  : https.createServer(
    {
      key: KEY_DATA,
      cert: CERT_DATA
    },
    app
  )

db.init().then(() => {
  logger.info('Database initialized')
  server.listen(PORT, () => {
    console.log(`Listening on ${PORT}`)
    // Database fixes go here
    User.updateAllKeys().then(() => {
      logger.info('Updated all keys')
    })
  })
})
