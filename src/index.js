const COOKIE = 'somiti_session';
const SESSION_DAYS = 7;
const ADMIN_EMAIL_DEFAULT = 'afazuddinsomiti@gmail.com';
const SHARE = 500;
const FINE = 50;
const CUTOFF = 15;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers }
  });
}
function uid(prefix='id') { return `${prefix}_${crypto.randomUUID()}`; }
function bytesToHex(buf) { return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join(''); }
async function sha256(text) { return bytesToHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))); }
async function hashPassword(password, salt = crypto.randomUUID()) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${salt}:${password}`));
  return `${salt}$${bytesToHex(digest)}`;
}
async function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || '').split('$');
  if (!salt || !hash) return false;
  return (await hashPassword(password, salt)) === stored;
}
function cookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
function todayISO(){ return new Date().toISOString().slice(0,10); }
function monthNow(){ return todayISO().slice(0,7); }
function isLate(date){ return Number(String(date).slice(8,10)) > CUTOFF; }
function validShares(x){ return [5,6,10].includes(Number(x)); }

async function session(req, env) {
  const raw = req.headers.get('Cookie') || '';
  const match = raw.match(new RegExp(`${COOKIE}=([^;]+)`));
  if (!match) return null;
  const tokenHash = await sha256(match[1]);
  return env.DB.prepare('SELECT email, expires_at FROM sessions WHERE token_hash=? AND expires_at>?').bind(tokenHash, Date.now()).first();
}
async function requireAdmin(req, env) { return await session(req, env); }
async function audit(env, email, action, entity='', entityId='') {
  await env.DB.prepare('INSERT INTO audit_log(id,email,action,entity,entity_id) VALUES(?,?,?,?,?)').bind(uid('audit'),email,action,entity,entityId).run();
}

async function ensureSchema(env) {
  const row = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='admins'").first();
  if (row) return;
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS members (id TEXT PRIMARY KEY, member_no INTEGER NOT NULL UNIQUE, name TEXT NOT NULL, position TEXT DEFAULT '', phone TEXT DEFAULT '', shares INTEGER NOT NULL CHECK (shares IN (5,6,10)), join_date TEXT DEFAULT '', active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS payments (id TEXT PRIMARY KEY, member_id TEXT NOT NULL, month TEXT NOT NULL, amount REAL NOT NULL, payment_date TEXT NOT NULL, notes TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(member_id) REFERENCES members(id) ON DELETE CASCADE)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS fund_transactions (id TEXT PRIMARY KEY, tx_date TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('income','investment','expense')), amount REAL NOT NULL, category TEXT DEFAULT '', description TEXT DEFAULT '', member_id TEXT, month TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(member_id) REFERENCES members(id) ON DELETE SET NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS admins (email TEXT PRIMARY KEY, password_hash TEXT NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, email TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, email TEXT NOT NULL, action TEXT NOT NULL, entity TEXT DEFAULT '', entity_id TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_payments_member_month ON payments(member_id, month)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_fund_date ON fund_transactions(tx_date)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at)")
  ]);
}

async function ensureAdmin(env) {
  const email = String(env.ADMIN_EMAIL || ADMIN_EMAIL_DEFAULT).trim().toLowerCase();
  const existing = await env.DB.prepare('SELECT email FROM admins WHERE email=?').bind(email).first();
  if (existing) return;
  if (!env.ADMIN_INITIAL_PASSWORD) throw new Error('ADMIN_INITIAL_PASSWORD secret is not configured');
  const password_hash = await hashPassword(env.ADMIN_INITIAL_PASSWORD);
  await env.DB.prepare('INSERT INTO admins(email,password_hash,must_change_password) VALUES(?,?,1)').bind(email,password_hash).run();
}

async function ensureSeed(env) {
  const row = await env.DB.prepare('SELECT COUNT(*) AS c FROM members').first();
  if (Number(row?.c || 0) > 0) return;
  const shares = [5,6,10];
  const stmt = env.DB.prepare('INSERT INTO members(id,member_no,name,position,phone,shares,join_date) VALUES(?,?,?,?,?,?,?)');
  const batch = [];
  for (let i=1;i<=50;i++) batch.push(stmt.bind(uid('m'),i,`সদস্য ${String(i).padStart(2,'0')}`,'','',shares[(i-1)%3],''));
  await env.DB.batch(batch);
}

async function state(env) {
  const [members, payments, fund] = await Promise.all([
    env.DB.prepare('SELECT id,member_no AS no,name,position,phone,shares,join_date AS joinDate FROM members WHERE active=1 ORDER BY member_no').all(),
    env.DB.prepare('SELECT id,member_id AS memberId,month,amount,payment_date AS date,notes FROM payments ORDER BY payment_date DESC').all(),
    env.DB.prepare("SELECT id,tx_date AS date,kind,amount,category,description,member_id AS memberId,month FROM fund_transactions ORDER BY tx_date DESC").all()
  ]);
  return {members:members.results||[],payments:payments.results||[],fund:fund.results||[],month:monthNow(),share:SHARE,finePerShare:FINE,cutoff:CUTOFF};
}

async function route(req, env) {
  await ensureSchema(env);
  await ensureAdmin(env);
  await ensureSeed(env);
  const url = new URL(req.url);

  if (url.pathname === '/api/state' && req.method === 'GET') return json(await state(env));
  if (url.pathname === '/api/me' && req.method === 'GET') {
    const s = await session(req, env);
    if (!s) return json({authenticated:false});
    const admin = await env.DB.prepare('SELECT email,must_change_password AS mustChangePassword FROM admins WHERE email=?').bind(s.email).first();
    return json({authenticated:true,...admin});
  }
  if (url.pathname === '/api/login' && req.method === 'POST') {
    const body = await req.json().catch(()=>({}));
    const email = String(body.email||'').trim().toLowerCase();
    const password = String(body.password||'');
    const admin = await env.DB.prepare('SELECT email,password_hash,must_change_password AS mustChangePassword FROM admins WHERE lower(email)=?').bind(email).first();
    if (!admin || !(await verifyPassword(password,admin.password_hash))) return json({error:'Invalid email or password'},401);
    const token = `${crypto.randomUUID()}-${crypto.randomUUID()}`;
    await env.DB.prepare('INSERT INTO sessions(token_hash,email,expires_at) VALUES(?,?,?)').bind(await sha256(token),admin.email,Date.now()+SESSION_DAYS*86400000).run();
    await audit(env,admin.email,'login');
    return json({ok:true,email:admin.email,mustChangePassword:!!admin.mustChangePassword},200,{'Set-Cookie':cookie(COOKIE,token,SESSION_DAYS*86400)});
  }
  if (url.pathname === '/api/logout' && req.method === 'POST') {
    const s=await session(req,env); if(s) await env.DB.prepare('DELETE FROM sessions WHERE email=?').bind(s.email).run();
    return json({ok:true},200,{'Set-Cookie':cookie(COOKIE,'',0)});
  }
  if (url.pathname === '/api/change-password' && req.method === 'POST') {
    const s=await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401);
    const body=await req.json().catch(()=>({})); const p=String(body.password||'');
    if(p.length<12) return json({error:'Password must be at least 12 characters'},400);
    await env.DB.prepare('UPDATE admins SET password_hash=?,must_change_password=0,updated_at=CURRENT_TIMESTAMP WHERE email=?').bind(await hashPassword(p),s.email).run();
    await audit(env,s.email,'change_password','admin',s.email); return json({ok:true});
  }
  if (url.pathname === '/api/members' && req.method === 'POST') {
    const s=await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401);
    const b=await req.json().catch(()=>({})); const id=b.id||uid('m');
    const no=Number(b.no), shares=Number(b.shares);
    if(!Number.isInteger(no)||no<1||!b.name||!validShares(shares)) return json({error:'Invalid member data'},400);
    try {
      if(b.id) await env.DB.prepare('UPDATE members SET member_no=?,name=?,position=?,phone=?,shares=?,join_date=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(no,String(b.name).trim(),b.position||'',b.phone||'',shares,b.join||'',id).run();
      else await env.DB.prepare('INSERT INTO members(id,member_no,name,position,phone,shares,join_date) VALUES(?,?,?,?,?,?,?)').bind(id,no,String(b.name).trim(),b.position||'',b.phone||'',shares,b.join||'').run();
    } catch(e) { return json({error:'Member number already exists or data is invalid'},400); }
    await audit(env,s.email,b.id?'update':'create','member',id); return json({ok:true,id});
  }
  if (url.pathname === '/api/payments' && req.method === 'POST') {
    const s=await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401);
    const b=await req.json().catch(()=>({}));
    const amount=Number(b.amount);
    if(!b.memberId||!/^\d{4}-\d{2}$/.test(b.month)||!Number.isFinite(amount)||amount<=0||!/^\d{4}-\d{2}-\d{2}$/.test(b.date)) return json({error:'Invalid payment'},400);
    const member=await env.DB.prepare('SELECT shares FROM members WHERE id=? AND active=1').bind(b.memberId).first();
    if(!member) return json({error:'Member not found'},404);
    const id=uid('p');
    await env.DB.prepare('INSERT INTO payments(id,member_id,month,amount,payment_date,notes) VALUES(?,?,?,?,?,?)').bind(id,b.memberId,b.month,amount,b.date,b.notes||'').run();
    await env.DB.prepare('INSERT INTO fund_transactions(id,tx_date,kind,amount,category,description,member_id,month) VALUES(?,?,?,?,?,?,?,?)').bind(uid('f'),b.date,'income',amount,'Member Payment','Member contribution',b.memberId,b.month).run();
    await audit(env,s.email,'create','payment',id); return json({ok:true,id});
  }
  if (url.pathname === '/api/fund' && req.method === 'POST') {
    const s=await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401);
    const b=await req.json().catch(()=>({})); const amount=Number(b.amount);
    if(!/^\d{4}-\d{2}-\d{2}$/.test(b.date)||!Number.isFinite(amount)||amount<=0||!['income','investment','expense'].includes(b.kind)) return json({error:'Invalid fund transaction'},400);
    const id=uid('f'); await env.DB.prepare('INSERT INTO fund_transactions(id,tx_date,kind,amount,category,description,member_id,month) VALUES(?,?,?,?,?,?,?,?)').bind(id,b.date,b.kind,amount,b.category||'',b.description||'',b.memberId||null,b.month||null).run();
    await audit(env,s.email,'create','fund',id); return json({ok:true,id});
  }
  if (url.pathname.startsWith('/api/fund/') && req.method === 'DELETE') {
    const s=await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401); const id=url.pathname.split('/').pop();
    await env.DB.prepare('DELETE FROM fund_transactions WHERE id=?').bind(id).run(); await audit(env,s.email,'delete','fund',id); return json({ok:true});
  }
  return json({error:'Not found'},404);
}

export default { async fetch(req,env,ctx) {
  const url=new URL(req.url);
  if(url.pathname.startsWith('/api/')) { try { return await route(req,env); } catch(e) { return json({error:'Server error',detail:String(e?.message||e)},500); } }
  return env.ASSETS.fetch(req);
}};
