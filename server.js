// Start: node server.js  ->  http://localhost:3000   (mit DATABASE_URL = Online-Datenbank, sonst data.json)
const http = require('http'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const DB = path.join(__dirname, 'data.json'), RANK = { user: 1, admin: 2, owner: 3, developer: 4 };
const pool = process.env.DATABASE_URL ? new (require('pg').Pool)({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } }) : null;
let db = { users: [], ann: [], log: [], sess: {}, duty: {}, shifts: [], abs: [], seq: 1 }, queue = Promise.resolve();
const save = () => { queue = queue.then(async () => {
  if (pool) await pool.query('INSERT INTO store(id,data) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET data=$1', [JSON.stringify(db)]);
  else fs.writeFileSync(DB, JSON.stringify(db, null, 1));
}).catch(x => console.error('Speichern fehlgeschlagen:', x.message)); };
const hash = (p, s = crypto.randomBytes(16).toString('hex')) => s + ':' + crypto.scryptSync(p, s, 32).toString('hex');
const check = (p, h) => { const [s, k] = h.split(':'); return crypto.timingSafeEqual(Buffer.from(k, 'hex'), crypto.scryptSync(p, s, 32)); };
const note = (by, text) => db.log.push({ t: Date.now(), by, text }); // Protokoll: wird nie gelöscht
async function load() {
  if (pool) {
    await pool.query('CREATE TABLE IF NOT EXISTS store(id int PRIMARY KEY, data jsonb NOT NULL)');
    const r = await pool.query('SELECT data FROM store WHERE id=1'); if (r.rows[0]) db = { ...db, ...r.rows[0].data };
  } else if (fs.existsSync(DB)) db = { ...db, ...JSON.parse(fs.readFileSync(DB)) };
  if (!db.users.length) { db.users.push({ id: db.seq++, username: '123', role: 'developer', pw: hash('123'), created: Date.now(), lastLogin: null }); note('System', 'Startkonto (Developer) angelegt'); }
  else if (!db.users.some(u => u.role === 'developer')) { // alte Daten: ältester Eigentümer wird Developer
    const o = db.users.filter(u => u.role === 'owner').sort((a, b) => a.id - b.id)[0];
    if (o) { o.role = 'developer'; note('System', 'Konto „' + o.username + '“ wurde zum Developer ernannt'); }
  }
  save();
}
const pub = u => ({ id: u.id, username: u.username, role: u.role, created: u.created, lastLogin: u.lastLogin });
const who = req => { const m = /sid=(\w+)/.exec(req.headers.cookie || ''); const id = m && db.sess[m[1]]; return db.users.find(x => x.id === id) || null; };
const lower = (a, t) => RANK[t.role] < RANK[a.role];            // Ziel steht strikt unter dem Handelnden
const canSee = (a, t) => t.id === a.id || lower(a, t);
const canDel = (a, t) => lower(a, t) && RANK[a.role] >= 2;      // löschen + Passwort zurücksetzen
const canRole = (a, t, r) => lower(a, t) && RANK[a.role] >= 3 && RANK[r] && RANK[r] <= RANK[a.role];
const canMake = (a, r) => RANK[a.role] >= 2 && RANK[r] && (a.role === 'admin' ? r === 'user' : RANK[r] <= RANK[a.role]);
const fail = (res, c, e) => { res.writeHead(c, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: e })); };
const ok = (res, d = { ok: 1 }, h = {}) => { res.writeHead(200, { 'Content-Type': 'application/json', ...h }); res.end(JSON.stringify(d)); };
const fails = {};

const server = http.createServer((req, res) => {
  let raw = ''; req.on('data', c => { raw += c; if (raw.length > 1e5) req.destroy(); });
  req.on('end', () => {
    const url = req.url.split('?')[0]; let b = {}; try { b = raw ? JSON.parse(raw) : {}; } catch { }
    if (!url.startsWith('/api/')) { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(fs.readFileSync(path.join(__dirname, 'index.html'))); }
    const r = url.slice(5).split('/'), M = req.method, me = who(req);
    if (r[0] === 'ping') return ok(res);
    if (r[0] === 'login' && M === 'POST') {
      const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim(), f = fails[ip] || (fails[ip] = { n: 0, until: 0 });
      if (Date.now() < f.until) return fail(res, 429, 'Zu viele Versuche – bitte eine Minute warten');
      const u = db.users.find(x => x.username === b.username);
      if (!u || !check(String(b.password || ''), u.pw)) { if (++f.n >= 5) { f.until = Date.now() + 60000; f.n = 0; } return setTimeout(() => fail(res, 401, 'Benutzername oder Passwort falsch'), 600); }
      f.n = 0; const t = crypto.randomBytes(24).toString('hex'); db.sess[t] = u.id; u.lastLogin = Date.now(); note(u.username, 'hat sich angemeldet'); save();
      return ok(res, pub(u), { 'Set-Cookie': `sid=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000` });
    }
    if (!me) return fail(res, 401, 'Nicht angemeldet');
    if (r[0] === 'logout') { delete db.sess[/sid=(\w+)/.exec(req.headers.cookie)[1]]; save(); return ok(res); }
    if (r[0] === 'me' && M === 'GET') return ok(res, pub(me));
    if (r[0] === 'me' && M === 'PATCH') {
      if (!b.old || !check(b.old, me.pw)) return fail(res, 403, 'Aktuelles Passwort falsch');
      const n = (b.username || me.username).trim(), p = b.password || null;
      if (n.length < 3 || (p && p.length < 3)) return fail(res, 400, 'Mindestens 3 Zeichen');
      if (db.users.some(x => x.username === n && x.id !== me.id)) return fail(res, 409, 'Benutzername vergeben');
      if (n !== me.username) note(me.username, 'hat den Benutzernamen zu „' + n + '“ geändert');
      if (p) { me.pw = hash(p); note(n, 'hat das eigene Passwort geändert'); }
      me.username = n; save(); return ok(res, pub(me));
    }
    if (r[0] === 'users' && !r[1] && M === 'GET') return ok(res, db.users.filter(t => canSee(me, t)).map(t => ({ ...pub(t), canDelete: canDel(me, t), canRole: canRole(me, t, 'user') })));
    if (r[0] === 'users' && !r[1] && M === 'POST') {
      const role = b.role || 'user';
      if (!canMake(me, role)) return fail(res, 403, 'Keine Berechtigung');
      const n = String(b.username || '').trim();
      if (n.length < 3 || n.length > 30 || String(b.password || '').length < 3) return fail(res, 400, 'Benutzername/Passwort mind. 3 Zeichen');
      if (db.users.some(x => x.username === n)) return fail(res, 409, 'Benutzername vergeben');
      db.users.push({ id: db.seq++, username: n, role, pw: hash(b.password), created: Date.now(), lastLogin: null });
      note(me.username, 'hat „' + n + '“ als ' + role + ' angelegt'); save(); return ok(res);
    }
    if (r[0] === 'users' && r[1]) {
      const t = db.users.find(x => x.id === +r[1]); if (!t) return fail(res, 404, 'Nicht gefunden');
      if (M === 'DELETE') {
        if (!canDel(me, t)) return fail(res, 403, 'Keine Berechtigung');
        db.users = db.users.filter(x => x !== t); for (const k in db.sess) if (db.sess[k] === t.id) delete db.sess[k];
        note(me.username, 'hat „' + t.username + '“ (' + t.role + ') gelöscht'); save(); return ok(res);
      }
      if (M === 'PATCH' && r[2] === 'role') {
        if (!canRole(me, t, b.role)) return fail(res, 403, 'Keine Berechtigung');
        note(me.username, 'hat „' + t.username + '“ von ' + t.role + ' zu ' + b.role + ' geändert'); t.role = b.role; save(); return ok(res);
      }
      if (M === 'PATCH' && r[2] === 'password') {
        if (!canDel(me, t)) return fail(res, 403, 'Keine Berechtigung');
        if (String(b.password || '').length < 3) return fail(res, 400, 'Mindestens 3 Zeichen');
        t.pw = hash(b.password); for (const k in db.sess) if (db.sess[k] === t.id) delete db.sess[k];
        note(me.username, 'hat das Passwort von „' + t.username + '“ zurückgesetzt'); save(); return ok(res);
      }
    }
    if (r[0] === 'ann' && M === 'GET') return ok(res, db.ann.slice().reverse());
    if (r[0] === 'ann' && M === 'POST') {
      if (RANK[me.role] < 2) return fail(res, 403, 'Keine Berechtigung');
      const text = String(b.text || '').trim(), title = String(b.title || '').trim();
      if (!title || !text) return fail(res, 400, 'Titel und Text nötig');
      db.ann.push({ id: db.seq++, title: title.slice(0, 100), text: text.slice(0, 2000), author: me.username, date: Date.now() });
      note(me.username, 'hat die Ankündigung „' + title.slice(0, 100) + '“ veröffentlicht'); save(); return ok(res);
    }
    if (r[0] === 'ann' && r[1] && M === 'DELETE') {
      if (RANK[me.role] < 2) return fail(res, 403, 'Keine Berechtigung');
      const a = db.ann.find(x => x.id === +r[1]); db.ann = db.ann.filter(x => x !== a);
      if (a) note(me.username, 'hat die Ankündigung „' + a.title + '“ gelöscht'); save(); return ok(res);
    }
    const today = () => new Date().toLocaleDateString('sv', { timeZone: 'Europe/Berlin' }), dOk = s => /^\d{4}-\d{2}-\d{2}$/.test(s || '');
    const vis = id => { const t = db.users.find(x => x.id === id); return t && canSee(me, t) ? t : null; };
    if (r[0] === 'status') return ok(res, { since: db.duty[me.id] || null });
    if (r[0] === 'duty' && M === 'POST') {
      if (b.on) { if (db.duty[me.id]) return fail(res, 409, 'Bereits im Dienst'); db.duty[me.id] = Date.now(); note(me.username, 'hat sich im Dienst angemeldet'); }
      else {
        const s = db.duty[me.id]; if (!s) return fail(res, 409, 'Nicht im Dienst'); const end = Date.now();
        db.shifts.push({ id: db.seq++, uid: me.id, name: me.username, start: s, end }); delete db.duty[me.id];
        note(me.username, 'hat sich vom Dienst abgemeldet (' + Math.round((end - s) / 60000) + ' Min.)');
      }
      save(); return ok(res);
    }
    if (r[0] === 'team') { const t = today(); return ok(res, db.users.map(u => ({ id: u.id, username: u.username, role: u.role, since: db.duty[u.id] || null, absent: db.abs.find(z => z.uid === u.id && z.status !== 'abgelehnt' && z.from <= t && z.to >= t) || null }))); }
    if (r[0] === 'shifts') return ok(res, db.shifts.filter(s => s.uid === me.id || vis(s.uid)).slice(-100).reverse());
    if (r[0] === 'abs' && M === 'GET') return ok(res, db.abs.filter(z => z.uid === me.id || vis(z.uid)).slice(-200).reverse().map(z => ({ ...z, canDecide: z.uid !== me.id && z.status === 'offen' && !!vis(z.uid) && RANK[me.role] >= 2, canRemove: z.uid === me.id || (!!vis(z.uid) && RANK[me.role] >= 2) })));
    if (r[0] === 'abs' && M === 'POST') {
      const reason = String(b.reason || '').trim().slice(0, 200);
      if (!dOk(b.from) || !dOk(b.to) || b.to < b.from) return fail(res, 400, 'Ungültiger Zeitraum');
      if (b.to < today()) return fail(res, 400, 'Der Zeitraum liegt in der Vergangenheit');
      if (!reason) return fail(res, 400, 'Bitte einen Grund angeben');
      db.abs.push({ id: db.seq++, uid: me.id, name: me.username, from: b.from, to: b.to, reason, status: 'offen', created: Date.now() });
      note(me.username, 'hat eine Abmeldung vom ' + b.from + ' bis ' + b.to + ' geplant'); save(); return ok(res);
    }
    if (r[0] === 'abs' && r[1]) {
      const z = db.abs.find(x => x.id === +r[1]); if (!z) return fail(res, 404, 'Nicht gefunden');
      const t = vis(z.uid);
      if (M === 'DELETE') {
        if (!(z.uid === me.id || (t && RANK[me.role] >= 2))) return fail(res, 403, 'Keine Berechtigung');
        db.abs = db.abs.filter(x => x !== z); note(me.username, 'hat die Abmeldung von „' + z.name + '“ (' + z.from + ' bis ' + z.to + ') entfernt'); save(); return ok(res);
      }
      if (M === 'PATCH') {
        if (z.uid === me.id || !t || RANK[me.role] < 2 || !['genehmigt', 'abgelehnt'].includes(b.status)) return fail(res, 403, 'Keine Berechtigung');
        z.status = b.status; z.by = me.username; note(me.username, 'hat die Abmeldung von „' + z.name + '“ ' + b.status); save(); return ok(res);
      }
    }
    if (r[0] === 'log' && M === 'GET') { if (RANK[me.role] < 3) return fail(res, 403, 'Keine Berechtigung'); return ok(res, db.log.slice(-500).reverse()); }
    fail(res, 404, 'Unbekannt');
  });
});
load().then(() => server.listen(process.env.PORT || 3000, () => console.log('Portal läuft auf Port ' + (process.env.PORT || 3000))))
  .catch(x => { console.error('Start fehlgeschlagen:', x.message); process.exit(1); });
