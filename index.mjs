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
import cors from 'cors'
import statuses from 'statuses'

// Configuration

const DATABASE = process.env.OPP_DATABASE || ':memory:'
const HOSTNAME = process.env.OPP_HOSTNAME || 'localhost'
const PORT = process.env.OPP_PORT || 65380
const KEY = process.env.OPP_KEY || 'localhost.key'
const CERT = process.env.OPP_CERT || 'localhost.crt'
const LOG_LEVEL = process.env.OPP_LOG_LEVEL || 'info'
const SESSION_SECRET =
  process.env.OPP_SESSION_SECRET || 'insecure-session-secret'
const INVITE_CODE = process.env.OPP_INVITE_CODE || null
const BLOCK_LIST = process.env.OPP_BLOCK_LIST || null
const ORIGIN =
  process.env.OPP_ORIGIN ||
  (PORT === 443 ? `https://${HOSTNAME}` : `https://${HOSTNAME}:${PORT}`)
const NAME = process.env.OPP_NAME || new URL(ORIGIN).hostname
const UPLOAD_DIR = process.env.OPP_UPLOAD_DIR || path.join(tmpdir(), nanoid())
const SQLITE3_CACHE = parseInt(process.env.OPP_SQLITE3_CACHE) || 16384
const MAXIMUM_TIME_SKEW = 5 * 60 * 1000 // 5 minutes
const MAINTENANCE_INTERVAL = 6 * 60 * 60 * 1000 // hourly maintenance

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
const SEC_CONTEXT = 'https://w3id.org/security/v1'
const BLOCKED_CONTEXT = 'https://purl.archive.org/socialweb/blocked'
const PENDING_CONTEXT = 'https://purl.archive.org/socialweb/pending'
const WEBFINGER_CONTEXT = 'https://purl.archive.org/socialweb/webfinger'
const MISCELLANY_CONTEXT = 'https://purl.archive.org/socialweb/miscellany'
const OAUTH_CONTEXT = 'https://purl.archive.org/socialweb/oauth/1.1'

const CONTEXT = [
  AS_CONTEXT,
  SEC_CONTEXT,
  BLOCKED_CONTEXT,
  PENDING_CONTEXT,
  WEBFINGER_CONTEXT,
  MISCELLANY_CONTEXT,
  OAUTH_CONTEXT
]

const LD_MEDIA_TYPE = 'application/ld+json'
const ACTIVITY_MEDIA_TYPE = 'application/activity+json'
const JSON_MEDIA_TYPE = 'application/json'
const ACCEPT_HEADER = `${LD_MEDIA_TYPE};q=1.0, ${ACTIVITY_MEDIA_TYPE};q=0.9, ${JSON_MEDIA_TYPE};q=0.3`
const PUBLIC = 'https://www.w3.org/ns/activitystreams#Public'
const PUBLICS = [
  PUBLIC,
  'as:Public',
  'Public'
]
const PUBLIC_OBJ = {
  id: PUBLIC,
  nameMap: { en: 'Public' },
  type: 'Collection'
}
const MAX_PAGE_SIZE = 20

// OAuth properties

const GRANT_TYPES_SUPPORTED = ['authorization_code', 'refresh_token']
const SCOPES_SUPPORTED = ['read', 'write']
const RESPONSE_TYPES_SUPPORTED = ['code']
const TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED = ['none']

// Functions

const jwtsign = promisify(jwt.sign)
const jwtverify = promisify(jwt.verify)
const generateKeyPair = promisify(crypto.generateKeyPair)

const isString = (value) =>
  typeof value === 'string' || value instanceof String

const isPublic = (id) => PUBLICS.includes(id)

const base64URLEncode = (str) =>
  str
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '')

function deepCopy (value) {
  return JSON.parse(JSON.stringify(value))
}

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

function equalDigests (digest1, digest2) {
  const [alg1, hash1] = digest1.split('=', 2)
  const [alg2, hash2] = digest2.split('=', 2)
  if (alg1.toLowerCase() !== alg2.toLowerCase()) {
    return false
  }
  return hash1 === hash2
}

function notIncluded (arr1, arr2) {
  return arr1.some(item => !arr2.includes(item))
}

class Counter {
  metrics = {}

  set (name, param = null, value = 0) {
    if (!this.metrics[name]) {
      this.metrics[name] = {}
    }
    if (param) {
      this.metrics[name][param] = value
    }
  }

  add (name, param, delta) {
    if (!this.metrics[name]) {
      this.metrics[name] = {}
    }
    if (!this.metrics[name][param]) {
      this.metrics[name][param] = 0
    }
    this.metrics[name][param] += delta
    return this.metrics[name][param]
  }

  increment (name, param) {
    return this.add(name, param, 1)
  }

  toHeader () {
    return Object.entries(this.metrics)
      .map(([name, params]) => [
        name,
        ...Object.entries(params).map(([param, value]) => `${param}=${value}`)
      ].join(';'))
      .join(', ')
  }

  get (name, param) {
    return (this.metrics[name])
      ? this.metrics[name][param]
      : undefined
  }
}

// Classes

class Database {
  #path = null
  #db = null
  #stmts = new Map()
  constructor (path) {
    this.#path = path
    this.#db = new sqlite3.Database(this.#path)
  }

  async init () {
    // Set up SQLite for best performance (hopefully)
    await this.run('PRAGMA journal_mode=WAL')
    await this.run('PRAGMA synchronous=NORMAL')
    await this.run('PRAGMA wal_autocheckpoint=1000')
    await this.run('PRAGMA busy_timeout=5000')
    await this.run('PRAGMA temp_store=MEMORY')
    await this.run(`PRAGMA cache_size=-${SQLITE3_CACHE}`)
    await this.run('PRAGMA optimize')

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
    await this.run(
      'CREATE TABLE IF NOT EXISTS remotecache (id VARCHAR(255), subject VARCHAR(255), expires DATETIME, data TEXT, complete BOOLEAN, PRIMARY KEY (id, subject))'
    )
    await this.run(
      'CREATE INDEX IF NOT EXISTS idx_remotecache_expires ON remotecache(expires)'
    )
    await this.run(
      'CREATE TABLE IF NOT EXISTS addressee_2 (objectId VARCHAR(255), addresseeId VARCHAR(255), PRIMARY KEY (objectId, addresseeId), FOREIGN KEY (objectId) REFERENCES object(id))'
    )
    await this.run(
      'CREATE INDEX IF NOT EXISTS idx_addressee_2_objectId ON addressee_2(objectId)'
    )
    await this.run(
      'INSERT OR IGNORE INTO addressee_2 SELECT * FROM addressee'
    )
    await this.run(
      'DELETE FROM addressee'
    )
    await this.run(
      'CREATE TABLE IF NOT EXISTS upload_2 (relative VARCHAR(255) PRIMARY KEY, mediaType VARCHAR(255), objectId VARCHAR(255), FOREIGN KEY (objectId) REFERENCES object(id))'
    )
    await this.run(
      'CREATE INDEX IF NOT EXISTS idx_upload_2_objectId ON upload_2(objectId)'
    )
    await this.run(
      'INSERT OR IGNORE INTO upload_2 SELECT * FROM upload'
    )
    await this.run(
      'DELETE FROM upload'
    )
    await this.run(
      'CREATE INDEX IF NOT EXISTS idx_user_actorId ON user(actorId)'
    )
    await this.run(
      'CREATE TABLE IF NOT EXISTS remote_failure (url VARCHAR(255), subject VARCHAR(255), status int, expires DATETIME, PRIMARY KEY (url, subject))'
    )

    // Create the public key for this server if it doesn't exist

    await Server.ensureKey()
  }

  async run (...params) {
    logger.silly('run() SQL: ' + params[0], params.slice(1))
    const qry = params[0]
    const stmt = this.getStmt(qry)
    return new Promise((resolve, reject) => {
      stmt.run(...params.slice(1), (err, results) => {
        stmt.reset()
        this.releaseStmt(stmt, qry)
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
    const qry = params[0]
    const stmt = this.getStmt(qry)
    return new Promise((resolve, reject) => {
      stmt.get(...params.slice(1), (err, results) => {
        stmt.reset()
        this.releaseStmt(stmt, qry)
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
    const qry = params[0]
    const stmt = this.getStmt(qry)
    return new Promise((resolve, reject) => {
      stmt.all(...params.slice(1), (err, results) => {
        stmt.reset()
        this.releaseStmt(stmt, qry)
        if (err) {
          reject(err)
        } else {
          resolve(results)
        }
      })
    })
  }

  async close () {
    for (const stmts of this.#stmts.values()) {
      for (const stmt of stmts) {
        stmt.finalize()
      }
    }
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

  getStmt (qry) {
    const stmts = this.#stmts.get(qry)
    let stmt
    if (Array.isArray(stmts) && stmts.length > 0) {
      stmt = stmts.shift()
    } else {
      stmt = this.#db.prepare(qry)
    }
    return stmt
  }

  releaseStmt (stmt, qry) {
    let stmts = this.#stmts.get(qry)
    if (Array.isArray(stmts)) {
      stmts.push(stmt)
    } else {
      stmts = [stmt]
      this.#stmts.set(qry, stmts)
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
        throw new Error(`Unsupported algorithm: ${parts.algorithm}`)
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
      this.header = `keyId="${this.keyId}",headers="(request-target) host date${this.digest ? ' digest' : ''
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

  async validate (req, cache = true) {
    const lines = []
    for (const name of this.headers.split(' ')) {
      if (name === '(request-target)') {
        lines.push(
          `(request-target): ${req.method.toLowerCase()} ${req.originalUrl}`
        )
      } else {
        const value = req.get(name)
        lines.push(`${name.toLowerCase()}: ${value.trim()}`)
      }
    }
    const data = lines.join('\n')
    const url = new URL(this.keyId)
    const fragment = url.hash ? url.hash.slice(1) : null
    url.hash = ''

    let options
    if (cache) {
      options = { counter: req.counter, cache: req.cache }
    } else {
      options = { counter: req.counter, skipRemoteCache: true }
    }
    const ao = await ActivityObject.get(url.toString(), options)

    if (!ao) {
      logger.warn(`Could not retrieve key id ${url.toString()}`)
      return null
    }

    let publicKey = null

    // Mastodon uses 'main-key' instead of 'publicKey'

    if (!fragment) {
      publicKey = ao
    } else if (fragment in (await ao.json())) {
      publicKey = await ActivityObject.get(await ao.prop(fragment), options)
    } else if (fragment === 'main-key' && 'publicKey' in (await ao.json())) {
      publicKey = await ActivityObject.get(await ao.prop('publicKey'), options)
    } else {
      return null
    }

    if (
      !publicKey ||
      !(await publicKey.json()) ||
      !(await publicKey.prop('owner')) ||
      !(await publicKey.prop('publicKeyPem'))
    ) {
      return null
    }

    const startTime = Date.now()
    const verifier = crypto.createVerify('sha256')
    verifier.write(data)
    verifier.end()
    const verified = verifier.verify(
      await publicKey.prop('publicKeyPem'),
      Buffer.from(this.signature, 'base64')
    )
    const endTime = Date.now()
    req.counter.increment('crypto', 'count')
    req.counter.add('crypto', 'dur', endTime - startTime)

    if (verified) {
      const ownerId = await publicKey.prop('owner')
      const owner = await ActivityObject.get(ownerId, options)
      await owner.cache()
      await publicKey.cache()
      return owner
    } else {
      return null
    }
  }

  static async authenticate (req, res, next) {
    const sigHeader = req.headers.signature
    if (sigHeader) {
      try {
        // Check for date header and time skew
        if (!req.headers.date) {
          return next(new createError.BadRequest('Missing date header'))
        }
        const date = new Date(req.headers.date)
        if (Math.abs(date.getTime() - Date.now()) > MAXIMUM_TIME_SKEW) {
          return next(new createError.BadRequest('Time skew detected'))
        }
        if (req.rawBodyText && req.rawBodyText.length !== 0) {
          if (!req.headers.digest) {
            return next(new createError.BadRequest('Missing digest header'))
          }
          const digest = req.headers.digest
          const calculated = digestBody(req.rawBodyText)
          if (!equalDigests(digest, calculated)) {
            logger.debug(`Digest mismatch: header "${digest}" != calculated "${calculated}"`)
            return next(new createError.BadRequest('Invalid digest header'))
          }
        }
        const signature = new HTTPSignature(sigHeader)

        // Try once with cache
        let remote = await signature.validate(req, true)
        if (!remote) {
          remote = await signature.validate(req, false)
        }
        if (remote) {
          req.auth = { subject: await remote.id() }
        } else {
          next(new createError.Unauthorized('Invalid HTTP signature'))
        }
      } catch (err) {
        logger.warn(`Error validating signature: ${err.message}`)
        logger.warn(`Signature: ${sigHeader}`)
        logger.debug(err.stack)
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
  #subject
  #cache
  #counter
  #skipRemoteCache
  static #DEFAULT_EXPIRES = 24 * 60 * 60 * 1000 // one day
  static #FAILURE_EXPIRES = 1 * 60 * 60 * 1000 // one hour
  constructor (data, options = {}) {
    const { subject, cache, counter, skipRemoteCache } = options
    if (!data) {
      throw new Error('No data provided')
    } else if (isString(data)) {
      this.#id = data
    } else if (typeof data === 'object') {
      if (data instanceof ActivityObject) {
        throw new Error('ActivityObject constructor with ActivityObject argument')
      }
      if (data instanceof Promise) {
        throw new Error('ActivityObject constructor with Promise as value')
      }
      if (Object.keys(data).length === 0) {
        throw new Error('Empty object in ActivityObject constructor')
      }
      this.#json = data
      this.#id = this.#json.id || this.#json['@id'] || null
    } else {
      throw new Error(`Unrecognized activity object: ${JSON.stringify(data)}`)
    }

    if (subject &&
        typeof subject === 'object' &&
        !(subject instanceof ActivityObject) &&
        Object.keys(subject).length === 0) {
      throw new Error('Empty object as subject in ActivityObject constructor')
    }

    this.#subject = subject
    this.#cache = cache
    this.#counter = counter
    this.#skipRemoteCache = skipRemoteCache
  }

  #options () {
    return {
      subject: this.#subject,
      cache: this.#cache,
      counter: this.#counter
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

  async prop (name) {
    if (this.#json && name in this.#json) {
      return this.#json[name]
    } else if (this.#id && (!this.#json || !this.#complete)) {
      await this.#getCompleteJSON()
      return (this.#json) ? this.#json[name] : undefined
    } else {
      return undefined
    }
  }

  async firstOf (names) {
    if (this.#json) {
      for (const name of names) {
        if (name in this.#json) {
          return [name, this.#json[name]]
        }
      }
    }
    if (this.#id && (!this.#json || !this.#complete)) {
      await this.#getCompleteJSON()
      for (const name of names) {
        if (name in this.#json) {
          return [name, this.#json[name]]
        }
      }
    }
    return [undefined, undefined]
  }

  async setProp (name, value) {
    if (this.#json) {
      this.#json[name] = value
    } else {
      this.#json = { [name]: value }
    }
    if (name === 'id') {
      this.#id = value
    }
  }

  async id () {
    if (!this.#id) {
      this.#id = this.#json?.id
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

  async ensureComplete () {
    if (!this.#complete) {
      await this.#getCompleteJSON()
    }
    return this.#json && this.#complete
  }

  async #getCompleteJSON () {
    if (!this.#id) {
      throw new Error("Can't get JSON without an ID")
    }
    if (this.#complete) {
      return
    }
    if (isPublic(this.#id)) {
      this.#json = PUBLIC_OBJ
      this.#complete = true
      return
    }
    if (ActivityObject.isRemoteId(this.#id)) {
      if (!this.#skipRemoteCache) {
        await this.#getJSONFromRemoteCache()
      }
      if (!this.#complete) {
        await this.#getJSONFromRemote()
      }
    } else {
      await this.#getJSONFromDatabase()
    }
    return this.#json
  }

  async #getJSONFromRemoteCache () {
    if (!this.#id) {
      throw new Error("Can't get JSON without an ID")
    }
    if (!ActivityObject.isRemoteId(this.#id)) {
      throw new Error(`Called remote cache for local object ${this.#id}`)
    }
    let [json, complete] = await this.getJSONFromRemoteCacheForSubject(this.#id, PUBLIC)
    if (json) {
      this.#json = json
      this.#complete = complete
    } else if (this.#subject) {
      [json, complete] = await this.getJSONFromRemoteCacheForSubject(
        this.#id,
        await toId(this.#subject)
      )
      if (json) {
        this.#json = json
        this.#complete = complete
      }
    }
  }

  async getJSONFromRemoteCacheForSubject (dataId, subjectId) {
    let json
    let complete = false
    const startTime = Date.now()
    const row = await db.get(
      'SELECT data, expires, complete FROM remotecache WHERE id = ? and subject = ?',
      [dataId, subjectId]
    )
    const endTime = Date.now()
    if (this.#counter) {
      this.#counter.add('db', 'dur', endTime - startTime)
      this.#counter.increment('db', 'count')
    }
    if (row) {
      if (row.expires > Date.now()) {
        const parseStartTime = Date.now()
        json = JSON.parse(row.data)
        const parseEndTime = Date.now()
        if (this.#counter) {
          this.#counter.add('json', 'dur', parseEndTime - parseStartTime)
          this.#counter.increment('json', 'count')
        }
        complete = row.complete
      } else {
        // Clean up expired cache object when seen
        await db.run(
          'DELETE FROM remotecache WHERE id = ? and subject = ?',
          [dataId, subjectId]
        )
      }
    }
    return [json, complete]
  }

  async #getJSONFromDatabase () {
    if (ActivityObject.isRemoteId(this.#id)) {
      throw new Error(`Cannot get remote object for ${this.#id}`)
    }
    const startTime = Date.now()
    const row = await db.get(
      'SELECT data FROM object WHERE id = ?',
      [this.#id]
    )
    const endTime = Date.now()
    if (this.#counter) {
      this.#counter.add('db', 'dur', endTime - startTime)
      this.#counter.increment('db', 'count')
    }
    if (!row) {
      this.#json = undefined
    } else {
      const parseStartTime = Date.now()
      this.#json = JSON.parse(row.data)
      const parseEndTime = Date.now()
      if (this.#counter) {
        this.#counter.add('json', 'dur', parseEndTime - parseStartTime)
        this.#counter.increment('json', 'count')
      }
      this.#complete = true
    }
    return this.#json
  }

  async #getJSONFromRemote (sign = true) {
    const date = new Date().toUTCString()
    const headers = {
      Date: date,
      Accept: ACCEPT_HEADER
    }
    let keyId = null
    let privKey = null
    if (this.#subject && (await User.isUser(this.#subject))) {
      const user = await User.fromActorId(await toId(this.#subject))
      const subjectObj = (this.#subject instanceof ActivityObject)
        ? this.#subject
        : new ActivityObject(this.#subject)
      keyId = await toId(await subjectObj.prop('publicKey'))
      privKey = user.privateKey
    } else {
      const server = await Server.get()
      keyId = server.keyId()
      privKey = server.privateKey()
    }
    const u = new URL(this.#id)
    const base = u.origin + u.pathname + u.search
    if (await this.failedBefore(base)) {
      logger.info(`Skipping fetch of ${base} for ${await this.#subject}`)
      return null
    }
    const signStartTime = Date.now()
    const signature = new HTTPSignature(keyId, privKey, 'GET', base, date)
    headers.Signature = signature.header
    const signEndTime = Date.now()
    if (this.#counter) {
      this.#counter.add('crypto', 'dur', signEndTime - signStartTime)
      this.#counter.increment('crypto', 'count')
    }
    logger.debug(`fetching ${this.#id} with key ID ${keyId}`)
    const startTime = Date.now()
    let res
    try {
      res = await fetch(base, { headers })
    } catch (err) {
      await this.rememberFailure(base, 0)
      return null
    }
    const endTime = Date.now()
    if (this.#counter) {
      this.#counter.add('http', 'dur', endTime - startTime)
      this.#counter.increment('http', 'count')
    }
    if (![200, 410].includes(res.status)) {
      const message = await res.text()
      logger.warn(`Error fetching ${this.#id}: ${res.status} ${res.statusText} (${message})`)
      await this.rememberFailure(base, res.status)
      this.#complete = false
      return null
    } else {
      const parseStartTime = Date.now()
      const json = await res.json()
      const parseEndTime = Date.now()
      if (this.#counter) {
        this.#counter.add('json', 'dur', parseEndTime - parseStartTime)
        this.#counter.increment('json', 'count')
      }
      const hash = (u.hash) ? u.hash.slice(1) : null
      if (!hash || hash.length === 0) {
        this.#json = json
      } else if (hash in json) {
        this.#json = json[hash]
      } else if (hash === 'main-key') { // Mastodon style
        this.#json = json.publicKey
      } else {
        logger.warn(`Can't resolve fragment ${hash} in ${this.#id}`)
        return null
      }
      this.#complete = true
      if (res.status === 410 && await this.type() !== 'Tombstone') {
        logger.warn(`Object ${this.#id} returned 410 but is not a Tombstone`)
        return null
      }
      await this.cache()
    }
  }

  async rememberFailure (url, status) {
    const subject = (await toId(this.#subject)) || (await Server.get()).id()
    logger.info(`Logging failure status ${status} for url ${url} with subject ${subject}`)
    await db.run('INSERT OR REPLACE INTO remote_failure (url, subject, status, expires) VALUES (?, ?, ?, ?)',
      [url, subject, status || 0,
        Date.now() + ActivityObject.#FAILURE_EXPIRES]
    )
  }

  async failedBefore (url) {
    const subject = (await toId(this.#subject)) || (await Server.get()).id()
    const row = await db.get(
      'SELECT expires FROM remote_failure WHERE url = ? AND subject = ?',
      [url, subject]
    )
    if (!row) {
      return false
    }
    if (row.expires > Date.now()) {
      return true
    }
    await db.run(
      'DELETE FROM remote_failure WHERE url = ? AND subject = ?',
      [url, subject]
    )
    return false
  }

  static async get (ref, options = {}) {
    if (options.cache) {
      const id = await toId(ref)
      if (id in options.cache) {
        if (options.counter) {
          options.counter.increment('cache', 'hit')
        }
        return options.cache[id]
      } else {
        if (options.counter) {
          options.counter.increment('cache', 'miss')
        }
      }
    }
    const obj = new ActivityObject(ref, options)
    if (await obj.ensureComplete()) {
      if (options.cache) {
        options.cache[obj.#id] = obj
      }
      return obj
    } else {
      return null
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
      await this.#getCompleteJSON()
    }
    return this.#json
  }

  async _setJson (json) {
    this.#json = json
  }

  async _hasJson () {
    return !!this.#json
  }

  async expand (subject = null) {
    const json = await this.expanded(subject)
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
        db.run('INSERT INTO addressee_2 (objectId, addresseeId) VALUES (?, ?)', [
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

  async cache (options = {}) {
    let { expires } = options
    if (!expires) {
      expires = Date.now() + ActivityObject.#DEFAULT_EXPIRES
    }
    const dataId = await this.id()
    if (!ActivityObject.isRemoteId(dataId)) {
      logger.warn('Skipping cache for local object', { dataId })
      return
    }
    const data = await this.json()
    const subjectId = (this.#subject)
      ? await toId(this.#subject)
      : PUBLIC

    const qry =
      'INSERT OR REPLACE INTO remotecache (id, subject, expires, data, complete) VALUES (?, ?, ?, ?, ?)'
    await db.run(qry, [dataId, subjectId, expires, JSON.stringify(data), this.#complete])
  }

  async clearCache () {
    if (!ActivityObject.isRemoteId(this.#id)) {
      return
    }
    await db.run('DELETE FROM remotecache WHERE id = ?', [this.#id])
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
      if (row && row.owner) {
        this.#owner = await ActivityObject.get(row.owner, this.#options())
      } else {
        let ownerRef
        for (const prop of ['attributedTo', 'actor', 'owner']) {
          ownerRef = await this.prop(prop)
          if (ownerRef) {
            break
          }
        }
        if (ownerRef) {
          this.#owner = new ActivityObject(ownerRef, this.#options())
        }
      }
    }
    return this.#owner
  }

  async addressees () {
    if (!this.#addressees) {
      const id = await this.id()
      const rows = await db.all(
        'SELECT addresseeId FROM addressee_2 WHERE objectId = ?',
        [id]
      )
      if (rows.length > 0) {
        this.#addressees = await Promise.all(
          rows.map((row) => ActivityObject.get(row.addresseeId, this.#options()))
        )
      } else {
        const addresseeIds = ActivityObject.guessAddressees(await this.json())
        this.#addressees = addresseeIds.map(id => new ActivityObject(id, this.#options()))
      }
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
      const obj = new ActivityObject(addresseeId)
      if (await obj.isCollection()) {
        const coll = new Collection(await obj.json())
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

  static isLinkType (ref) {
    return (typeof ref === 'object' && ['Link', 'Hashtag', 'Mention'].includes(ref.type))
  }

  async isLinkType () {
    return ActivityObject.isLinkType(await this.json())
  }

  async brief () {
    let brief = (await this.isLinkType())
      ? {
          href: await this.prop('href'),
          type: await this.type()
        }
      : {
          id: await this.id(),
          type: await this.type(),
          icon: await this.prop('icon')
        }

    const [prop, value] = await this.firstOf(['nameMap', 'name', 'summaryMap', 'summary'])
    if (prop) {
      brief[prop] = value
    }
    switch (await this.type()) {
      case 'Key':
      case 'PublicKey':
      case 'CryptographicKey':
        brief = {
          ...brief,
          owner: await this.prop('owner'),
          publicKeyPem: await this.prop('publicKeyPem')
        }
        break
      case 'Note':
        brief = {
          ...brief,
          content: await this.prop('content'),
          contentMap: await this.prop('contentMap')
        }
        break
      case 'OrderedCollection':
      case 'Collection':
        if (!isPublic(this.#id)) {
          brief = {
            ...brief,
            first: await toId(await this.prop('first'))
          }
        }
        break
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
    'to'
  ]

  static #linkProps = [
    'url'
  ]

  static #arrayProps = ['items', 'orderedItems']

  async expanded () {
    await this.ensureComplete()
    if (!this.#json) {
      if (this.#id) {
        return this.#id
      } else {
        return undefined
      }
    }
    const object = deepCopy(this.#json)
    const toBrief = async (value) => {
      if (!value) {
        return value
      } else if (ActivityObject.isLinkType(value)) {
        return deepCopy(value)
      } else {
        const obj = await ActivityObject.get(
          value,
          this.#options()
        )
        return await obj.brief()
      }
    }

    await Promise.all(ActivityObject.#idProps.map(async (prop) => {
      if (prop in object) {
        const original = object[prop]
        try {
          if (Array.isArray(object[prop])) {
            object[prop] = await Promise.all(object[prop].map(toBrief))
          } else if (prop === 'object' && (await this.needsExpandedObject())) {
            const obj = await ActivityObject.get(object[prop], this.#options())
            object[prop] = await obj.expanded()
          } else {
            object[prop] = await toBrief(object[prop])
          }
        } catch (error) {
          logger.warn(`Error while expanding ${prop} of ${this.#id}: ${JSON.stringify(object[prop])}`)
          // Leave it unexpanded
          object[prop] = deepCopy(original)
        }
      }
    }))

    await Promise.all(ActivityObject.#linkProps.map(async (prop) => {
      if (typeof object[prop] === 'string') {
        object[prop] = {
          type: 'Link',
          href: object[prop]
        }
      }
    }))

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
    if (!json) {
      return false
    } else {
      return prop in json
    }
  }

  static isRemoteId (id) {
    return id && !id.startsWith(ORIGIN)
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
      'INSERT INTO addressee_2 (objectId, addresseeId) VALUES (?, ?)',
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
      { subject: actor }
    )
    const appliers = {
      Follow: async () => {
        const objectProp = await this.prop('object')
        if (!objectProp) {
          throw new createError.BadRequest('No object followed')
        }
        const other = new ActivityObject(objectProp, { subject: actor })
        if (!other) {
          throw new createError.BadRequest(
            `No such object to follow: ${JSON.stringify(objectProp)}`
          )
        }
        await other.ensureComplete()
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
          { subject: actorObj }
        )
        switch (await accepted.type()) {
          case 'Follow': {
            const pendingFollowers = new Collection(
              await actorObj.prop('pendingFollowers')
            )
            await pendingFollowers.expand(actorObj)
            if (!(await pendingFollowers.hasMember(await accepted.id()))) {
              throw new createError.BadRequest(
                'Not awaiting acceptance for follow'
              )
            }
            const other = await ActivityObject.get(
              await accepted.prop('actor'),
              { subject: actorObj }
            )
            const isUser = await User.isUser(other)
            let pendingFollowing = null
            if (isUser) {
              pendingFollowing = new Collection(
                await other.prop('pendingFollowing')
              )
              await pendingFollowers.expand(actorObj)
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
          { subject: actorObj }
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
              { subject: actorObj }
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
            { subject: actorObj }
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
        const object = await ActivityObject.get(
          activity.object.id,
          { subject: actorObj }
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
              `Update mismatch for ${prop}: ${activity.object[prop]
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
          { subject: actorObj }
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
        logger.debug(`deleted object summaryMap.en: ${(await object.prop('summaryMap')).en}`)
        return activity
      },
      Add: async () => {
        if (!activity.object) {
          throw new createError.BadRequest('No object to add')
        }
        const object = await ActivityObject.get(
          activity.object,
          { subject: actorObj }
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
          { subject: actorObj }
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
          { subject: actorObj }
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
          { subject: actorObj }
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
          { subject: actorObj }
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
          { subject: actorObj }
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
              { subject: actorObj }
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
              { subject: actorObj }
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
              { subject: actorObj }
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
              { subject: actorObj }
            )
            const sharedObjectOwner = await sharedObject.owner()
            if (await User.isUser(sharedObjectOwner)) {
              await sharedObject.expand(actorObj)
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
          if (isPublic(addressee)) {
            const followers = new Collection(await owner.prop('followers'))
            return await followers.members()
          } else {
            const obj = new ActivityObject(addressee, { subject: owner })
            if (await obj.isCollection()) {
              const coll = new Collection(addressee, { subject: owner })
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
      let other = await ActivityObject.get(addressee, { subject: owner })
      if (await User.isUser(other)) {
        // Local delivery
        await other.expand(owner)
        logger.debug(`Local delivery for ${activity.id} to ${addressee}`)
        const inbox = new Collection(await other.prop('inbox'))
        await inbox.prependData(activity)
      } else {
        logger.debug(`Remote delivery for ${activity.id} to ${addressee}`)
        other = await ActivityObject.get(addressee, { subject: owner })
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
  static async get (ref, options = {}) {
    const ao = await super.get(ref, options)
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

  async hasMember (object, subject = null) {
    await this.ensureComplete()
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
        await page.expand(subject)
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
    if (!data) {
      throw new Error('No data to prepend')
    } else if (Array.isArray(data)) {
      throw new Error('Cannot prepend an array')
    } else if (typeof data === 'object' && !data.id) {
      throw new Error('Cannot prepend data without an id')
    }
    return await this.prepend(new ActivityObject(data))
  }

  async prepend (object) {
    await this.ensureComplete()
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
      await first.ensureComplete()
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
        const attributedTo = await this.prop('attributedTo')
        if (!attributedTo) {
          throw new Error(`No owner for collection ${await this.id()}`)
        } else if (attributedTo instanceof Promise) {
          throw new Error('owner is a promise when adding page')
        } else {
          logger.debug(`Got owner adding a page: ${JSON.stringify(attributedTo)}`)
        }
        const props = {
          type: firstJson.type,
          partOf: collection.id,
          next: firstJson.id,
          attributedTo: await toId(attributedTo)
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
    if (owner instanceof Promise) {
      throw new Error('Got a promise as an owner')
    }
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
    let ref = await this.prop('first')
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
    throw new Error("Can't save a remote object")
  }

  async apply (remote = null, addressees = null, ...args) {
    const owner = args[0]
    const ownerObj = await ActivityObject.get(owner)
    if (!remote) {
      remote = await ActivityObject.get(
        await this.prop('actor'),
        { subject: ownerObj }
      )
    }
    if (!addressees) {
      addressees = ActivityObject.guessAddressees(await this.json())
    }

    const remoteObj = remote
    const remoteAppliers = {
      Follow: async () => {
        const object = await ActivityObject.get(
          await this.prop('object'),
          { subject: ownerObj }
        )
        if ((await object.id()) === (await ownerObj.id())) {
          const followers = await Collection.get(
            await ownerObj.prop('followers'),
            { subject: ownerObj }
          )
          if (await followers.hasMember(remote)) {
            throw new Error('Already a follower')
          }
          const pendingFollowers = await Collection.get(
            await ownerObj.prop('pendingFollowers'),
            { subject: ownerObj }
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
          const ao = new ActivityObject(await this.prop('object'), { subject: ownerObj })
          const owner = await ao.owner()
          if (owner && (await owner.id()) !== (await remoteObj.id())) {
            throw new Error('Cannot create something you do not own!')
          }
          await ao.cache()
          if (await ao.prop('inReplyTo')) {
            const inReplyTo = new ActivityObject(await ao.prop('inReplyTo'))
            await inReplyTo.expand(ownerObj)
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
          const ao = new ActivityObject(await this.prop('object'), { subject: ownerObj })
          const aoOwner = await ao.owner()
          if (aoOwner && (await aoOwner.id()) !== (await remoteObj.id())) {
            throw new Error('Cannot update something you do not own!')
          }
          logger.debug(`Clearing cache on update for ${await ao.id()}`)
          await ao.clearCache()
          if (await ao.prop('inReplyTo')) {
            const inReplyTo = new ActivityObject(await ao.prop('inReplyTo'))
            await inReplyTo.expand(ownerObj)
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
          const ao = new ActivityObject(await this.prop('object'), { subject: ownerObj })
          const aoOwner = await ao.owner()
          if (aoOwner && (await aoOwner.id()) !== (await remoteObj.id())) {
            throw new Error('Cannot delete something you do not own!')
          }
          logger.debug(`Clearing cache on delete for ${await ao.id()}`)
          await ao.clearCache()
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
            await ao.expand(ownerObj)
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
            await ao.expand(ownerObj)
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
            } else {
              logger.debug(`Clearing cache on add for ${await target.id()}`)
              await target.clearCache()
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
            } else {
              logger.debug(`Clearing cache on remove for ${await target.id()}`)
              await target.clearCache()
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
        const undone = new ActivityObject(objectProp, { subject: ownerObj })
        const actorProp = await undone.prop('actor')
        if (!actorProp) {
          throw new Error('No actor!')
        }
        const undoneActor = new ActivityObject(actorProp, { subject: ownerObj })
        if ((await remoteObj.id()) !== (await undoneActor.id())) {
          throw new Error('Not your activity to undo!')
        }
        switch (await undone.type()) {
          case 'Like': {
            const objectProp = await undone.prop('object')
            const object = new ActivityObject(objectProp, { subject: ownerObj })
            if (!(await object.canRead(await remoteObj.id()))) {
              throw new Error('Cannot unlike something you cannot read!')
            }
            const objectOwner = await object.owner()
            if (await User.isUser(objectOwner)) {
              await object.expand(ownerObj)
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
              await object.expand(ownerObj)
              const shares = new Collection(await object.prop('shares'))
              await shares.remove(undone)
            }
            break
          }
          case 'Follow': {
            const objectProp = await undone.prop('object')
            const object = new ActivityObject(objectProp, { subject: ownerObj })
            if (!(await object.canRead(await remoteObj.id()))) {
              throw new Error('Cannot unfollow something you cannot read!')
            }
            const objectOwner = await object.owner()
            if (await User.isUser(objectOwner)) {
              const followers = new Collection(
                await object.prop('followers'),
                { subject: ownerObj }
              )
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
      type: 'CryptographicKey',
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

  // Make sure all our actors are self-owned and publicly viewable

  static async updateAllUsers () {
    const rows = await db.all('select actorId from user')
    for (const row of rows) {
      const actorId = row.actorId
      const actor = await ActivityObject.get(actorId)
      if (!actor.attributedTo) {
        logger.info('Adding attributedTo to actor', { id: actorId })
        await actor.patch({ attributedTo: actorId })
      }
      if (!actor.to) {
        logger.info('Adding to to actor', { id: actorId })
        await actor.patch({ to: PUBLIC })
      }
    }
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

  static async updateAllCollections () {
    const rows = await db.all('SELECT * FROM user')
    let count = 0
    for (const row of rows) {
      const user = await User.fromRow(row)
      const actor = await ActivityObject.get(user.actorId)
      const props = ['inbox', 'outbox', 'followers', 'following', 'liked']
      for (const prop of props) {
        const coll = await ActivityObject.get(await actor.prop(prop), { subject: actor })
        count += await User.updateCollection(user, coll, actor, PUBLIC)
      }
      for (const prop of props) {
        const coll = await ActivityObject.get(await actor.prop(prop), { subject: actor })
        let pageRef = await coll.prop('first')
        while (pageRef) {
          const page = await ActivityObject.get(pageRef, { subject: actor })
          count += await User.updateCollection(user, page, actor, (prop === 'inbox') ? null : PUBLIC)
          pageRef = await page.prop('next')
        }
      }
      const priv = ['blocked', 'pendingFollowing', 'pendingFollowers']
      for (const prop of priv) {
        const coll = await ActivityObject.get(await actor.prop(prop))
        count += await User.updateCollection(user, coll, actor, null)
        let pageRef = await coll.prop('first')
        while (pageRef) {
          const page = await ActivityObject.get(pageRef, { subject: actor })
          count += await User.updateCollection(user, page, actor, null)
          pageRef = await page.prop('next')
        }
      }
    }
    logger.info(`Updated ${count} collections and collection pages`)
  }

  static async updateCollection (user, coll, actor, to) {
    const patch = {}
    const at = await coll.prop('attributedTo')
    if (!at ||
      (typeof at === 'object' && Object.keys(at).length === 0) ||
      await toId(at) !== await toId(actor)) {
      patch.attributedTo = await actor.id()
    }
    if (to && !await coll.prop('to')) {
      patch.to = to
    } else if (!to && await coll.prop('to')) {
      patch.to = null
    }
    if (Object.keys(patch).length > 0) {
      logger.info(`Updating user collection ${await coll.id()} for ${await actor.id()} to correct permissions`)
      await user.internalUpdate(
        coll,
        patch,
        to,
        actor
      )
      return 1
    } else {
      return 0
    }
  }

  async internalUpdate (ao, patch, to, actor) {
    try {
      await ao.patch(patch)
      const data = {
        id: await ActivityObject.makeId('Update'),
        to: to || undefined,
        type: 'Update',
        object: await ao.id(),
        actor: await actor.id()
      }
      const activity = new Activity(data, { subject: actor })
      await activity.save()
      const outbox = await Collection.get(await actor.prop('outbox'))
      await outbox.prepend(activity)
      const inbox = await Collection.get(await actor.prop('inbox'))
      await inbox.prepend(activity)
      pq.add(activity.distribute())
    } catch (err) {
      logger.error(err)
    }
  }

  async doActivity (data) {
    const actor = await this.getActor()
    const ownerId = await actor.id()
    const outbox = new Collection(await actor.prop('outbox'))
    data.id = await ActivityObject.makeId(data.type)
    data.actor = ownerId
    const activity = new Activity(data, { subject: ownerId })
    await activity.apply()
    await activity.save()
    await outbox.prepend(activity)
    const inbox = new Collection(await actor.prop('inbox'))
    await inbox.prepend(activity)
    pq.add(activity.distribute())
    return activity
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
    const row = await db.get('SELECT * FROM upload_2 WHERE relative = ?', [
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
      'INSERT INTO upload_2 (relative, mediaType, objectId) VALUES (?, ?, ?)',
      [this.relative, this.mediaType, this.objectId]
    )
  }
}

// Server

const { combine, timestamp, errors, splat, printf } = winston.format

const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: combine(
    timestamp(),
    errors({ stack: true }),
    splat(),
    printf(({ timestamp, level, message, stack, ...rest }) => {
      const meta = Object.keys(rest).length ? ` ${JSON.stringify(rest)}` : ''
      return `${timestamp} ${level}: ${stack || message}${meta}`
    })
  ),
  transports: [new winston.transports.Console()]
})

// verbose output

sqlite3.verbose()

// Initialize SQLite
const db = new Database(DATABASE)

// Initialize PromiseQueue

const pq = new PromiseQueue()
pq.add(async () => { })

// Initialize Express
const app = express()

// Initialize Multer
const upload = multer({ storage: multer.memoryStorage() })

app.use((req, res, next) => {
  req.counter = new Counter()
  req.counter.set('db', 'dur', 0)
  req.counter.set('db', 'count', 0)
  req.counter.set('http', 'dur', 0)
  req.counter.set('http', 'count', 0)
  req.counter.set('crypto', 'dur', 0)
  req.counter.set('crypto', 'count', 0)
  req.counter.set('json', 'dur', 0)
  req.counter.set('json', 'count', 0)
  req.counter.set('app', 'dur', 0)
  const startTime = Date.now()
  const oldWriteHead = res.writeHead
  res.writeHead = function (statusCode, statusMessage, headers) {
    const endTime = Date.now()
    req.counter.add('app', 'dur', endTime - startTime)
    res.setHeader('Server-Timing', req.counter.toHeader())
    return oldWriteHead.call(this, statusCode, statusMessage, headers)
  }
  next()
})

// per-request ActivityObject cache
app.use((req, res, next) => {
  req.cache = {}
  req.counter.set('cache', 'dur', 0)
  req.counter.set('cache', 'hit', 0)
  req.counter.set('cache', 'miss', 0)
  next()
})

// log every request
app.use((req, res, next) => {
  const oldEnd = res.end
  res.end = function (...args) {
    const subject = req.auth?.subject || '-'
    const duration = req.counter.get('app', 'dur')
    logger.info(
      `${res.statusCode} ${req.method} ${req.url}`,
      { subject, duration }
    )
    oldEnd.apply(this, args)
  }
  next()
})

app.use(cors({
  maxAge: 86400
}))

app.use(
  express.json({
    type: [
      'application/json',
      'application/activity+json',
      'application/ld+json'
    ],
    verify: (req, res, buf, encoding) => {
      req.rawBodyText = buf.toString(encoding || 'utf8')
    }
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

  static async get (counter = null) {
    if (!Server.#singleton) {
      const origin = makeUrl('')
      const startTime = Date.now()
      const row = await db.get('SELECT * FROM server where origin = ?', [
        origin
      ])
      const endTime = Date.now()
      if (counter) {
        counter.increment('db', 'count')
        counter.add('db', 'dur', endTime - startTime)
      }
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

  id () {
    return this.#origin
  }

  toJSON () {
    return {
      '@context': CONTEXT,
      id: this.#origin,
      type: 'Service',
      name: process.OPP_NAME || 'One Page Pub',
      preferredUsername: URL.parse(this.#origin).host,
      publicKey: {
        type: 'CryptographicKey',
        id: this.keyId(),
        owner: this.#origin,
        publicKeyPem: this.#publicKey
      }
    }
  }

  getKeyJSON () {
    return {
      '@context': CONTEXT,
      type: 'CryptographicKey',
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
    req.server = await Server.get(req.counter)
    req.jwtKeyData = req.server.privateKey()
    return next()
  })
)

async function jwtOptional (req, res, next) {
  const startTime = Date.now()
  const mw = expressjwt({
    credentialsRequired: false,
    secret: req.jwtKeyData,
    algorithms: ['RS256']
  })
  return mw(req, res, (err) => {
    const endTime = Date.now()
    req.counter.add('crypto', 'dur', endTime - startTime)
    next(err)
  })
}

async function jwtRequired (req, res, next) {
  const startTime = Date.now()
  const mw = expressjwt({
    credentialsRequired: true,
    secret: req.jwtKeyData,
    algorithms: ['RS256']
  })
  return mw(req, res, (err) => {
    const endTime = Date.now()
    req.counter.add('crypto', 'dur', endTime - startTime)
    next(err)
  })
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

app.get(
  '/',
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
      const server = req.server
      res.set('Content-Type', 'application/activity+json')
      res.json(await server.toJSON())
    } else {
      const acceptHeader = req.get('Accept')
      logger.warn(`Cannot satisfy Accept header requirements: ${acceptHeader}`)
      res.status(406).send('Not Acceptable')
    }
  })
)

app.get(
  '/key',
  wrap(async (req, res) => {
    const server = req.server
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
              ${user
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
            One Page Pub ${version ? `<span class="version">${version}</span>` : ''
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
      ${!INVITE_CODE || INVITE_CODE.length === 0
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
  wrap(async (req, res) => {
    const resource = req.query.resource
    if (!resource) {
      throw new createError.BadRequest('Missing resource')
    }
    let jrd
    if (resource.startsWith('acct:')) {
      if (!resource.includes('@')) {
        throw new createError.BadRequest('Resource must contain @')
      }
      const [username, hostname] = resource.substr('acct:'.length).split('@')
      if (hostname !== req.get('host')) {
        throw new createError.NotFound('Hostname does not match')
      }

      if (username === hostname) { // Server ID
        jrd = {
          subject: resource,
          links: [
            {
              rel: 'self',
              type: 'application/activity+json',
              href: `https://${hostname}/`
            }
          ]
        }
      } else {
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

        jrd = {
          subject: resource,
          links: [
            {
              rel: 'self',
              type: 'application/activity+json',
              href: user.actorId
            }
          ]
        }
      }
    } else if (resource.startsWith('https:')) {
      let url
      try {
        url = URL.parse(resource)
      } catch (error) {
        throw new createError.BadRequest('URL parse error')
      }
      if (url.host !== req.get('host')) {
        throw new createError.BadRequest('Hostname mismatch')
      }
      const user = await User.fromActorId(resource)
      if (!user) {
        throw new createError.NotFound('User not found')
      }

      jrd = {
        subject: `acct:${user.username}@${req.get('host')}`,
        links: [
          {
            rel: 'self',
            type: 'application/activity+json',
            href: user.actorId
          }
        ]
      }
    } else {
      throw new createError.BadRequest('Unsupported protocol')
    }

    res.set('Content-Type', 'application/jrd+json')
    res.json(jrd)
  })
)

app.get(
  '/.well-known/oauth-authorization-server',
  wrap(async (req, res) => {
    res.status(200)
    res.json({
      issuer: ORIGIN,
      authorization_endpoint: makeUrl('endpoint/oauth/authorize'),
      token_endpoint: makeUrl('endpoint/oauth/token'),
      registration_endpoint: makeUrl('endpoint/oauth/registration'),
      scopes_supported: SCOPES_SUPPORTED,
      response_types_supported: RESPONSE_TYPES_SUPPORTED,
      grant_types_supported: GRANT_TYPES_SUPPORTED,
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
      activitypub_universal_client_id: true,
      client_id_metadata_document_supported: true
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
    logger.debug(`Getting ${id} in proxyUrl`)
    const user = await User.fromActorId(req.auth?.subject)
    if (!user) {
      throw new createError.InternalServerError('Invalid user')
    }
    if (!req.auth.scope || !req.auth.scope.split(' ').includes('read')) {
      throw new createError.Unauthorized('Missing read scope')
    }
    const options = { cache: req.cache, counter: req.counter }
    const actor = await ActivityObject.get(req.auth?.subject, options)
    options.subject = actor
    const obj = await ActivityObject.get(id, options)

    if (!obj) {
      throw new createError.NotFound('Object not found')
    }

    res.status((await obj.type() === 'Tombstone') ? 410 : 200)
    res.set('Content-Type', 'application/activity+json')
    res.json(await obj.json())
  })
)

app.get(
  '/endpoint/oauth/authorize',
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
      const clientId = req.query.client_id
      let clientIdUrl = null
      let client = null
      try {
        clientIdUrl = new URL(clientId)
      } catch {
        logger.warn('Invalid client ID URL format', { clientId })
        throw new createError.BadRequest('Invalid client_id')
      }
      if (clientIdUrl.protocol !== 'https:') {
        logger.warn('Invalid client ID protocol', { clientId })
        throw new createError.BadRequest('Invalid client_id')
      }
      if (ActivityObject.isRemoteId(clientId)) {
        let res = null
        try {
          res = await fetch(clientId, {
            headers: { Accept: ACCEPT_HEADER }
          })
        } catch (err) {
          logger.warn(
            'Cannot fetch client ID',
            { clientId, error: err.message }
          )
          throw new createError.BadRequest('Invalid client_id')
        }
        if (!res.ok) {
          logger.warn(
            'Bad status code fetching client ID',
            { clientId, statusCode: res.statusCode }
          )
          throw new createError.BadRequest('Invalid client_id')
        }
        let json = null
        try {
          json = await res.json()
        } catch (err) {
          logger.warn('Could not get client as JSON', { clientId, err })
          throw new createError.BadRequest('Invalid client_id')
        }
        if (json.client_id) {
          client = await clientFromCimd(json)
        } else if (json.id) {
          client = new ActivityObject(json)
        } else {
          logger.warn('Unrecognised client JSON', { clientId, json })
          throw new createError.BadRequest('Invalid client_id')
        }
      } else {
        try {
          client = await ActivityObject.get(clientId)
        } catch (err) {
          logger.warn(
            'Error getting client',
            { clientId, error: err.message }
          )
          throw new createError.BadRequest('Invalid client_id')
        }
      }
      if (!client) {
        logger.warn(
          'No client object returned',
          { clientId }
        )
        throw new createError.BadRequest('Invalid client_id')
      }
      if (!req.query.redirect_uri) {
        throw new createError.BadRequest('Missing redirect_uri')
      }
      if (req.query.redirect_uri !== (await client.prop('redirectURI'))) {
        logger.warn(
          'Redirect URI mismatch',
          {
            queryParam: req.query.redirect_uri,
            clientProp: await client.prop('redirectURI')
          }
        )
        throw new createError.BadRequest('Invalid redirect_uri')
      }
      if (!req.query.response_type || req.query.response_type !== 'code') {
        logger.warn(
          'missing or invalid response_type',
          {
            clientId,
            responseType: req.query.response_type
          }
        )
        throw new createError.BadRequest('Missing or invalid response_type')
      }
      if (!req.query.scope) {
        logger.warn('missing scope', { clientId })
        throw new createError.BadRequest('Missing scope')
      }
      if (!req.query.code_challenge) {
        logger.warn('missing code_challenge', { clientId })
        throw new createError.BadRequest('Missing code_challenge')
      }
      if (
        !req.query.code_challenge_method ||
        req.query.code_challenge_method !== 'S256'
      ) {
        logger.warn('bad code_challenge_method', {
          clientId,
          method: req.query.code_challenge_method
        })
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
          <li>Client ID: ${clientId}</li>
          <li>Name: ${name
            ? url
              ? `<a target="_blank" href="${url}">${name}</a>`
              : name
            : 'N/A'
          }</li>
          <li>Icon: ${icon ? `<img src="${icon}" >` : 'N/A'}</li>
          <li>Description: ${description || 'N/A'}</li>
          <li>Author: ${author
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
      <input type="hidden" name="client_id" value="${clientId}" />
      <input type="hidden" name="redirect_uri" value="${req.query.redirect_uri
          }" />
      <input type="hidden" name="scope" value="${req.query.scope}" />
      <input type="hidden" name="code_challenge" value="${req.query.code_challenge
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

class InvalidRedirectURIError extends Error {}
class InvalidClientMetadataError extends Error {}

async function clientFromCimd (body) {
  if (
    !Array.isArray(body.redirect_uris) ||
    body.redirect_uris.length === 0) {
    throw new InvalidRedirectURIError('redirect_uris required')
  }
  body.redirect_uris.forEach((redirectUri) => {
    let url = null
    try {
      url = new URL(redirectUri)
    } catch (err) {
      throw new InvalidRedirectURIError(
        `${redirectUri} is not a valid URL`
      )
    }
    if (url.protocol !== 'https:') {
      throw new InvalidRedirectURIError(
        `${redirectUri} is not an HTTPS URL`
      )
    }
  })
  if (Array.isArray(body.grant_types) &&
    notIncluded(body.grant_types, GRANT_TYPES_SUPPORTED)) {
    throw new InvalidClientMetadataError(`Unsupported grant type (only ${JSON.stringify(GRANT_TYPES_SUPPORTED)} supported)`)
  }
  if (Array.isArray(body.response_types) &&
    notIncluded(body.response_types, RESPONSE_TYPES_SUPPORTED)) {
    throw new InvalidClientMetadataError(`Unsupported response type (only ${JSON.stringify(RESPONSE_TYPES_SUPPORTED)} supported)`)
  }
  if (Array.isArray(body.scope) &&
    notIncluded(body.scope, SCOPES_SUPPORTED)) {
    throw new InvalidClientMetadataError(`Unsupported scope (only ${JSON.stringify(SCOPES_SUPPORTED)} supported)`)
  }
  if (body.token_endpoint_auth_method &&
    !TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED.includes(body.token_endpoint_auth_method)) {
    throw new InvalidClientMetadataError(`Unsupported token endpoint auth method (only ${JSON.stringify(TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED)} supported)`)
  }

  const server = await Server.get()

  const client = new ActivityObject({
    '@context': CONTEXT,
    name: body.client_name,
    redirectURI:
      (body.redirect_uris.length === 1)
        ? body.redirect_uris[0]
        : body.redirect_uris,
    attributedTo: await server.id(),
    to: PUBLIC
  })

  return client
}

app.post(
  '/endpoint/oauth/registration',
  wrap(async (req, res) => {
    try {
      const contentTypeHeader = req.get('Content-Type')
      if (!contentTypeHeader) {
        throw new InvalidClientMetadataError('Invalid Content-Type')
      }
      const mediaType = contentTypeHeader.split(';')[0].trim()
      if (mediaType !== 'application/json') {
        throw new InvalidClientMetadataError('Invalid Content-Type')
      }
      const body = req.body
      const client = await clientFromCimd(body)
      await client.save()
      res.status(201)
      res.json({
        client_id: await client.id(),
        redirect_uris: body.redirect_uris,
        client_name: body.client_name
      })
    } catch (err) {
      let errorType = null
      if (err instanceof InvalidClientMetadataError) {
        errorType = 'invalid_client_metadata'
      } else if (err instanceof InvalidRedirectURIError) {
        errorType = 'invalid_redirect_uri'
      } else {
        throw err
      }
      res.status(400)
      res.json({
        error: errorType,
        error_description: err.message
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
      data.object.url = {
        href: makeUrl(`/uploads/${uploaded.relative}`),
        type: 'Link',
        mediaType: uploaded.mediaType
      }
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
    const output = {
      '@context': CONTEXT,
      ...(await activity.expanded())
    }
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
  HTTPSignature.authenticate,
  wrap(async (req, res) => {
    const full = makeUrl(req.originalUrl)
    const counter = req.counter
    const cache = req.cache
    if (
      req.auth &&
      req.auth.scope &&
      !req.auth.scope.split(' ').includes('read')
    ) {
      throw new createError.Forbidden('Missing read scope')
    }
    const subject = req.auth?.subject
    const options = { subject, counter, cache }
    const obj = await ActivityObject.get(full, options)
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
    let output = await obj.expanded()
    const name = ['items', 'orderedItems'].find(prop =>
      prop in output && Array.isArray(output[prop]))
    if (name) {
      output[name] = (await Promise.all(output[name].map(async (value) => {
        const item = await ActivityObject.get(value, options)
        if (!item) {
          return { id: await toId(value) }
        } else if (!(await item.canRead(req.auth?.subject))) {
          return null
        } else {
          return await item.expanded()
        }
      }))).filter(Boolean)
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

      output.universalClientID = true
    }
    if (output.type === 'Tombstone') {
      res.status(410)
    }
    output = {
      '@context': CONTEXT,
      ...output
    }
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
      const user = await User.fromActorId(await owner.id())
      const activity = await user.doActivity(data)
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
      const remote = await ActivityObject.get(req.auth.subject, { subject: owner })
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
        logger.debug(`New remote activity from ${actorId}`)
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
      await activity.cache()
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

app.use((req, res, next) => {
  throw new createError.NotFound('No such route')
})

app.use((err, req, res, next) => {
  let type, status, title, detail
  if (createError.isHttpError(err)) {
    if (err.statusCode >= 500) {
      logger.error(`Error status ${err.statusCode}: `, err)
      logger.debug(err.stack)
    } else if (err.statusCode >= 400 && err.statusCode < 500) {
      logger.warn(`Error ${err.statusCode} processing ${req.url}: ${err.message}`)
      logger.debug(err.stack)
    }
    status = err.statusCode
    detail = err.message
  } else if (['UnauthorizedError', 'JWTTypeError'].includes(err.name)) {
    status = 401
    detail = err.message
    res.set(
      'WWW-Authenticate',
      'Bearer error="invalid_token", error_description="Not a valid access token"'
    )
  } else {
    logger.error('Error status 500: ', err)
    logger.debug(err.stack)
    status = 500
    detail = err.message
  }
  res.status(status)
  res.set('Content-Type', 'application/problem+json')
  res.json({
    type: type || 'about:blank',
    title: title || statuses(status),
    status,
    detail
  })
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

const fixups = [
  User.updateAllUsers,
  User.updateAllKeys,
  User.updateAllCollections,
  async () => {
    // We used to store remote data in the same table as local data
    // This moves the remote data to the cache table
    logger.info('Copying addressed remote data from object to remotecache')
    const affected = await db.run(
      `INSERT OR IGNORE INTO remotecache (id, subject, expires, data, complete)
       SELECT o.id, a2.addresseeId, ?, o.data, TRUE
       FROM object o JOIN addressee_2 a2 ON o.id = a2.objectId
       WHERE o.id NOT LIKE ?`, [Date.now() + 30 * 24 * 60 * 60 * 1000, `${ORIGIN}%`]
    )
    logger.info(`Rows affected: ${affected}`)
    logger.info('Deleting addressee_2 rows for remote data')
    await db.run(
      'DELETE FROM addressee_2 WHERE EXISTS (select id from remotecache rc where rc.id = addressee_2.objectId)'
    )
    logger.info('Deleting object rows for remote data')
    await db.run(
      'DELETE FROM object WHERE EXISTS (select id from remotecache rc where rc.id = object.id) and object.id NOT LIKE ?', [`${ORIGIN}%`]
    )
  }
]

const maintenance = [
  async () => {
    const ts = Date.now()
    const { beforeCount } = await db.get(
      'SELECT count(*) AS beforeCount FROM remotecache WHERE expires < ?',
      [ts])
    if (beforeCount === 0) {
      return 'No stale remote cache objects'
    } else {
      await db.run('DELETE FROM remotecache WHERE expires < ?', [Date.now()])
      const { afterCount } = await db.get(
        'SELECT count(*) AS afterCount FROM remotecache WHERE expires < ?',
        [ts])
      return `Deleted ${beforeCount - afterCount} stale rows from remote cache`
    }
  },
  async () => {
    const ts = Date.now()
    const { beforeCount } = await db.get(
      'SELECT count(*) AS beforeCount FROM remote_failure WHERE expires < ?',
      [ts])
    if (beforeCount === 0) {
      return 'No stale remote failure objects'
    } else {
      await db.run('DELETE FROM remote_failure WHERE expires < ?', [Date.now()])
      const { afterCount } = await db.get(
        'SELECT count(*) AS afterCount FROM remote_failure WHERE expires < ?',
        [ts])
      return `Deleted ${beforeCount - afterCount} stale rows from remote cache`
    }
  }
]

function runAllMaintenance () {
  for (const maint of maintenance) {
    maint()
      .then((msg) => logger.info(msg))
      .catch((err) => logger.error(err))
  }
}

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

db.init()
  .then(() => {
    logger.info('Database initialized')
    server.listen(PORT, () => {
      console.log(`Listening on ${PORT}`)
      for (const fixup of fixups) {
        fixup()
          .then((result) => {
            logger.info(result)
          })
          .catch((error) => {
            logger.error(error)
          })
      }
      runAllMaintenance()
      setInterval(runAllMaintenance, MAINTENANCE_INTERVAL)
    })
  })
  .catch((err) => {
    logger.error('Database initialization failed')
    logger.error(err)
    logger.info('Shutting down')
  })
