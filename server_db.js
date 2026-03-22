'use strict';
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const DB_PATH = path.join(__dirname, '..', 'data', 'db.json');
const dataDir = path.dirname(DB_PATH);
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

function read() {
  try { return JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); }
  catch { return { users:{}, investigations:{}, sessions:{}, loginAttempts:{} }; }
}
function write(data) {
  const tmp = DB_PATH + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, DB_PATH);
}
function getDB() {
  const db = read();
  db.users          = db.users          || {};
  db.investigations = db.investigations || {};
  db.sessions       = db.sessions       || {};
  db.loginAttempts  = db.loginAttempts  || {};
  return db;
}

// ── Password hashing (scrypt) ───────────────────────────────────
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1 };
const KEY_LEN = 64;

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(32).toString('hex');
    crypto.scrypt(password, salt, KEY_LEN, SCRYPT_PARAMS, (err, key) => {
      if (err) reject(err);
      else resolve(`scrypt$${salt}$${key.toString('hex')}`);
    });
  });
}
function verifyPassword(password, stored) {
  return new Promise((resolve, reject) => {
    const parts = stored.split('$');
    if (parts.length !== 3 || parts[0] !== 'scrypt') { resolve(false); return; }
    const [, salt, hash] = parts;
    crypto.scrypt(password, salt, KEY_LEN, SCRYPT_PARAMS, (err, key) => {
      if (err) { reject(err); return; }
      try {
        const a = Buffer.from(key.toString('hex'));
        const b = Buffer.from(hash);
        resolve(a.length === b.length && crypto.timingSafeEqual(a, b));
      } catch { resolve(false); }
    });
  });
}

// ── Sessions ────────────────────────────────────────────────────
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

function createSession(userId) {
  const token = crypto.randomBytes(48).toString('hex');
  const db = getDB();
  db.sessions[token] = { userId, createdAt: Date.now(), expiresAt: Date.now() + SESSION_TTL_MS };
  write(db);
  return token;
}
function validateSession(token) {
  if (!token) return null;
  const db   = getDB();
  const sess = db.sessions[token];
  if (!sess) return null;
  if (Date.now() > sess.expiresAt) { delete db.sessions[token]; write(db); return null; }
  return sess.userId;
}
function deleteSession(token) { const db=getDB(); delete db.sessions[token]; write(db); }
function cleanExpiredSessions() {
  const db=getDB(), now=Date.now(); let changed=false;
  for (const [token,sess] of Object.entries(db.sessions)) {
    if (now > sess.expiresAt) { delete db.sessions[token]; changed=true; }
  }
  if (changed) write(db);
}

// ── Brute-force ─────────────────────────────────────────────────
const MAX_ATTEMPTS = 5, LOCKOUT_MS = 15*60*1000, ATTEMPT_WIN = 10*60*1000;

function checkBruteForce(identifier) {
  const db=getDB(), key=`bf_${identifier}`, rec=db.loginAttempts[key];
  if (!rec) return { allowed:true };
  const now=Date.now();
  if (rec.lockedUntil && now < rec.lockedUntil)
    return { allowed:false, retryAfter:Math.ceil((rec.lockedUntil-now)/1000) };
  return { allowed:true };
}
function recordLoginAttempt(identifier, success) {
  const db=getDB(), key=`bf_${identifier}`, now=Date.now();
  if (!db.loginAttempts[key]) db.loginAttempts[key]={ attempts:[], lockedUntil:null };
  const rec=db.loginAttempts[key];
  if (success) { delete db.loginAttempts[key]; write(db); return; }
  rec.attempts=[...(rec.attempts||[]).filter(t=>now-t<ATTEMPT_WIN),now];
  if (rec.attempts.length>=MAX_ATTEMPTS) {
    rec.lockedUntil=now+LOCKOUT_MS;
    console.warn(`[Auth] Locked: ${identifier}`);
  }
  write(db);
}

// ── Users — now with nickname + role ───────────────────────────
const VALID_ROLES = ['SOC Analyst Tier 1','SOC Analyst Tier 2','SOC Analyst Tier 3',
  'Threat Intelligence Analyst','Malware Analyst','Incident Responder',
  'Security Engineer','Penetration Tester','Manager / Team Lead','Other'];

async function createUser(username, password, nickname, role) {
  const db = getDB();
  if (db.users[username]) throw new Error('Username already exists');
  const hashed  = await hashPassword(password);
  const safeNick = (nickname||'').trim().slice(0,50) || username;
  const safeRole = VALID_ROLES.includes(role) ? role : 'SOC Analyst';
  const user = {
    id        : crypto.randomBytes(16).toString('hex'),
    username,
    password  : hashed,
    nickname  : safeNick,
    role      : safeRole,
    createdAt : new Date().toISOString(),
  };
  db.users[username] = user;
  write(db);
  return { id:user.id, username:user.username, nickname:user.nickname, role:user.role, createdAt:user.createdAt };
}

async function loginUser(username, password, ip) {
  const bfUser=checkBruteForce(username), bfIP=checkBruteForce(ip);
  if (!bfUser.allowed) throw new Error(`Too many failed attempts. Try again in ${bfUser.retryAfter}s.`);
  if (!bfIP.allowed)   throw new Error(`Too many failed attempts from this IP. Try again in ${bfIP.retryAfter}s.`);
  const db=getDB(), user=db.users[username];
  if (!user) {
    await new Promise(r=>setTimeout(r,200+Math.random()*100));
    recordLoginAttempt(username,false); recordLoginAttempt(ip,false);
    throw new Error('Invalid username or password');
  }
  const valid=await verifyPassword(password,user.password);
  if (!valid) {
    recordLoginAttempt(username,false); recordLoginAttempt(ip,false);
    throw new Error('Invalid username or password');
  }
  recordLoginAttempt(username,true); recordLoginAttempt(ip,true);
  return { id:user.id, username:user.username, nickname:user.nickname||user.username, role:user.role||'SOC Analyst', createdAt:user.createdAt };
}

function getUserById(userId) {
  const db=getDB();
  for (const u of Object.values(db.users)) {
    if (u.id===userId) return { id:u.id, username:u.username, nickname:u.nickname||u.username, role:u.role||'SOC Analyst', createdAt:u.createdAt };
  }
  return null;
}

// ── Investigations ──────────────────────────────────────────────
function saveInvestigation(userId,ioc,iocType,results,aiAnalysis) {
  const db=getDB(), id=crypto.randomBytes(16).toString('hex');
  const inv={ id,userId,ioc,iocType,results,aiAnalysis,comments:[],createdAt:new Date().toISOString(),updatedAt:new Date().toISOString() };
  if (!db.investigations[userId]) db.investigations[userId]={};
  db.investigations[userId][id]=inv; write(db);
  return inv;
}
function getInvestigations(userId) {
  const db=getDB();
  return Object.values(db.investigations[userId]||{}).sort((a,b)=>new Date(b.createdAt)-new Date(a.createdAt));
}
function getInvestigation(userId,invId) { return getDB().investigations[userId]?.[invId]||null; }
function deleteInvestigation(userId,invId) {
  const db=getDB();
  if (db.investigations[userId]?.[invId]) { delete db.investigations[userId][invId]; write(db); return true; }
  return false;
}

// ── Comments ────────────────────────────────────────────────────
function addComment(userId,invId,text) {
  const db=getDB(), inv=db.investigations[userId]?.[invId];
  if (!inv) throw new Error('Investigation not found');
  const c={ id:crypto.randomBytes(8).toString('hex'), text:text.trim(), createdAt:new Date().toISOString() };
  inv.comments=inv.comments||[]; inv.comments.push(c); inv.updatedAt=new Date().toISOString();
  write(db); return c;
}
function deleteComment(userId,invId,commentId) {
  const db=getDB(), inv=db.investigations[userId]?.[invId];
  if (!inv) throw new Error('Investigation not found');
  const before=(inv.comments||[]).length;
  inv.comments=(inv.comments||[]).filter(c=>c.id!==commentId);
  if (inv.comments.length===before) throw new Error('Comment not found');
  inv.updatedAt=new Date().toISOString(); write(db); return true;
}

module.exports = {
  hashPassword, verifyPassword,
  createSession, validateSession, deleteSession, cleanExpiredSessions,
  checkBruteForce, recordLoginAttempt,
  createUser, loginUser, getUserById, VALID_ROLES,
  saveInvestigation, getInvestigations, getInvestigation, deleteInvestigation,
  addComment, deleteComment,
};
