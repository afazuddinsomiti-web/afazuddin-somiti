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
function validShares(x){ const n=Number(x); return Number.isInteger(n) && n>=0 && n<=10; }

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
  // Always ensure every application table exists. The migration creates the
  // core tables, but older databases may be missing newer tables such as
  // rules. Using IF NOT EXISTS keeps existing data intact.
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS rules (id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS members (id TEXT PRIMARY KEY, member_no INTEGER NOT NULL UNIQUE, name TEXT NOT NULL, position TEXT DEFAULT '', phone TEXT DEFAULT '', shares INTEGER NOT NULL CHECK (shares >= 0 AND shares <= 10), profile_photo TEXT DEFAULT '', join_date TEXT DEFAULT '', active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS payments (id TEXT PRIMARY KEY, member_id TEXT NOT NULL, month TEXT NOT NULL, amount REAL NOT NULL, payment_date TEXT NOT NULL, notes TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(member_id) REFERENCES members(id) ON DELETE CASCADE)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS fund_transactions (id TEXT PRIMARY KEY, tx_date TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('income','investment','expense')), amount REAL NOT NULL, category TEXT DEFAULT '', description TEXT DEFAULT '', member_id TEXT, month TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(member_id) REFERENCES members(id) ON DELETE SET NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS admins (email TEXT PRIMARY KEY, password_hash TEXT NOT NULL, must_change_password INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, email TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS audit_log (id TEXT PRIMARY KEY, email TEXT NOT NULL, action TEXT NOT NULL, entity TEXT DEFAULT '', entity_id TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS organizational_fund_transactions (id TEXT PRIMARY KEY, tx_date TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('income','expense')), category TEXT NOT NULL, amount REAL NOT NULL, donor_name TEXT DEFAULT '', description TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_payments_member_month ON payments(member_id, month)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_fund_date ON fund_transactions(tx_date)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at)"),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_org_fund_date ON organizational_fund_transactions(tx_date)")
  ]);
  const orgCols = await env.DB.prepare("PRAGMA table_info(organizational_fund_transactions)").all();
  if (!(orgCols.results || []).some(c => c.name === 'donor_name')) {
    await env.DB.prepare("ALTER TABLE organizational_fund_transactions ADD COLUMN donor_name TEXT DEFAULT ''").run();
  }
}

async function ensureAdmin(env) {
  const email = String(env.ADMIN_EMAIL || ADMIN_EMAIL_DEFAULT).trim().toLowerCase();
  const existing = await env.DB.prepare('SELECT email FROM admins WHERE email=?').bind(email).first();
  if (existing) return true;

  // Never block the public site just because the optional initial-password
  // secret is missing. If the admin account does not exist yet, login will
  // return a clear configuration error instead of a generic Server error.
  if (!env.ADMIN_INITIAL_PASSWORD) return false;

  const password_hash = await hashPassword(env.ADMIN_INITIAL_PASSWORD);
  await env.DB.prepare(
    'INSERT INTO admins(email,password_hash,must_change_password) VALUES(?,?,1)'
  ).bind(email,password_hash).run();
  return true;
}

async function ensureSeed(env) {
  const memberRows = await env.DB.prepare('SELECT member_no FROM members ORDER BY member_no').all();
  const existing = new Set((memberRows.results || []).map(r => Number(r.member_no)));
  const shares = [5,6,10];
  const stmt = env.DB.prepare('INSERT INTO members(id,member_no,name,position,phone,shares,profile_photo,join_date) VALUES(?,?,?,?,?,?,?,?)');
  const batch = [];
  for (let i=1;i<=50;i++) {
    if (!existing.has(i)) batch.push(stmt.bind(uid('m'),i,`সদস্য ${String(i).padStart(2,'0')}`,'','',shares[(i-1)%3],'',''));
  }
  if (batch.length) await env.DB.batch(batch);

  const ruleCount = await env.DB.prepare('SELECT COUNT(*) AS c FROM rules').first();
  if (Number(ruleCount?.c || 0) === 0) {
    const ruleStmt = env.DB.prepare('INSERT INTO rules(id,title,body) VALUES(?,?,?)');
    const rules = [
      ['১. মাসিক চাঁদা','প্রতি Share-এর নির্ধারিত মাসিক চাঁদা সময়মতো পরিশোধ করতে হবে।'],
      ['২. চাঁদা জমার সময়সীমা','প্রতি মাসের ১৫ তারিখের মধ্যে মাসিক চাঁদা জমা দেওয়ার চেষ্টা করতে হবে।'],
      ['৩. বিলম্ব জরিমানা','১৫ তারিখের পর বকেয়া Share-এর জন্য নির্ধারিত জরিমানা প্রযোজ্য হবে।'],
      ['৪. একাধিক Share','প্রত্যেক সদস্যের অনুমোদিত Share সংখ্যা অনুযায়ী মাসিক চাঁদা হিসাব করা হবে।'],
      ['৫. সদস্যদের হিসাব','প্রত্যেক সদস্যের জমা, বকেয়া ও জরিমানার হিসাব অ্যাপে সংরক্ষণ করা হবে।'],
      ['৬. সদস্য তথ্য পরিবর্তন','নাম, পদবি, মোবাইল ও Share-এর তথ্য পরিবর্তনের প্রয়োজন হলে Admin-এর মাধ্যমে আপডেট করতে হবে।'],
      ['৭. তহবিলের ব্যবহার','সমিতির সাধারণ তহবিল সমিতির অনুমোদিত প্রয়োজন ও কার্যক্রমে ব্যবহার করা হবে।'],
      ['৮. সাংগঠনিক ফান্ড','যাকাত, ফিতরা, স্বেচ্ছা দান, জরিমানা ও অন্যান্য সকল তহবিলের আয়-ব্যয়ের হিসাব আলাদা খাতে রাখা হবে।'],
      ['৯. আয়-ব্যয়ের স্বচ্ছতা','সমিতির আয় ও ব্যয়ের হিসাব নিয়মিত সংরক্ষণ ও পর্যালোচনা করা হবে।'],
      ['১০. সাংগঠনিক সিদ্ধান্ত','সমিতির গুরুত্বপূর্ণ সাংগঠনিক সিদ্ধান্ত আলোচনা ও সম্মতির ভিত্তিতে গ্রহণ করা হবে।'],
      ['১১. সদস্যদের দায়িত্ব','প্রত্যেক সদস্যকে সমিতির নিয়ম মেনে চলতে এবং নির্ধারিত সময়ের মধ্যে নিজের দায়িত্ব পালন করতে হবে।'],
      ['১২. শৃঙ্খলা','সমিতির সকল সদস্যকে পরস্পরের প্রতি সম্মানজনক আচরণ করতে হবে এবং অপ্রয়োজনীয় বিরোধ এড়িয়ে চলতে হবে।'],
      ['১৩. হিসাব সংরক্ষণ','সমিতির হিসাব, লেনদেন ও প্রয়োজনীয় নথি নিরাপদভাবে সংরক্ষণ করা হবে।'],
      ['১৪. নিয়ম পরিবর্তন','প্রয়োজন হলে Admin বা সমিতির অনুমোদিত সিদ্ধান্তের মাধ্যমে এই নিয়মগুলো সংশোধন বা নতুন নিয়ম যোগ করা যাবে।'],
      ['১৫. মূলনীতি','একতায় শক্তি, ঐক্যেই সমাধান—পারস্পরিক সহযোগিতা ও বিশ্বাসের মাধ্যমে সমিতির কার্যক্রম পরিচালিত হবে।']
    ];
    await env.DB.batch(rules.map(([title,body]) => ruleStmt.bind(uid('rule'),title,body)));
  }
}

async function state(env) {
  const [members, cancelledMembers, payments, fund, orgFund, rules] = await Promise.all([
    env.DB.prepare('SELECT id,member_no AS no,name,position,phone,shares,profile_photo AS photo,join_date AS joinDate FROM members WHERE active=1 ORDER BY member_no').all(),
    env.DB.prepare('SELECT id,member_no AS no,name,position,phone,shares,profile_photo AS photo,join_date AS joinDate,updated_at AS cancelledAt FROM members WHERE active=0 ORDER BY member_no').all(),
    env.DB.prepare('SELECT id,member_id AS memberId,month,amount,payment_date AS date,notes FROM payments ORDER BY payment_date DESC').all(),
    env.DB.prepare("SELECT id,tx_date AS date,kind,amount,category,description,member_id AS memberId,month FROM fund_transactions ORDER BY tx_date DESC").all(),
    env.DB.prepare("SELECT id,tx_date AS date,kind,category,amount,donor_name AS donorName,description FROM organizational_fund_transactions ORDER BY tx_date DESC").all(),
    env.DB.prepare("SELECT id,title,body,created_at AS createdAt,updated_at AS updatedAt FROM rules ORDER BY created_at DESC").all()
  ]);
  return {members:members.results||[],cancelledMembers:cancelledMembers.results||[],payments:payments.results||[],fund:fund.results||[],orgFund:orgFund.results||[],rules:rules.results||[],month:monthNow(),share:SHARE,finePerShare:FINE,cutoff:CUTOFF};
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
    if (!admin) return json({error:'Admin account is not configured. Cloudflare Worker-এ ADMIN_INITIAL_PASSWORD secret সেট করুন।'},503);
    if (!(await verifyPassword(password,admin.password_hash))) return json({error:'Invalid email or password'},401);
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
    const photo=typeof b.photo==='string'?b.photo:'';
    if(photo.length>700000) return json({error:'Profile photo is too large. Please choose a smaller image.'},400);
    try {
      if(b.id) await env.DB.prepare('UPDATE members SET member_no=?,name=?,position=?,phone=?,shares=?,profile_photo=?,join_date=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(no,String(b.name).trim(),b.position||'',b.phone||'',shares,photo,b.join||'',id).run();
      else await env.DB.prepare('INSERT INTO members(id,member_no,name,position,phone,shares,profile_photo,join_date) VALUES(?,?,?,?,?,?,?,?)').bind(id,no,String(b.name).trim(),b.position||'',b.phone||'',shares,photo,b.join||'').run();
    } catch(e) { return json({error:'Member number already exists or data is invalid'},400); }
    await audit(env,s.email,b.id?'update':'create','member',id); return json({ok:true,id});
  }
  if (url.pathname.startsWith('/api/members/') && req.method === 'DELETE') {
    const s=await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401);
    const id=url.pathname.split('/').pop();
    const member=await env.DB.prepare('SELECT id,name FROM members WHERE id=? AND active=1').bind(id).first();
    if(!member) return json({error:'Member not found'},404);
    // Soft-delete so old payments and financial history remain intact.
    await env.DB.prepare('UPDATE members SET active=0,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(id).run();
    await audit(env,s.email,'deactivate','member',id);
    return json({ok:true,id});
  }
  if (url.pathname.startsWith('/api/members/') && url.pathname.endsWith('/restore') && req.method === 'POST') {
    const s=await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401);
    const id=url.pathname.split('/').slice(-2,-1)[0];
    const member=await env.DB.prepare('SELECT id,name FROM members WHERE id=? AND active=0').bind(id).first();
    if(!member) return json({error:'Cancelled member not found'},404);
    await env.DB.prepare('UPDATE members SET active=1,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(id).run();
    await audit(env,s.email,'restore','member',id);
    return json({ok:true,id});
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
  if (url.pathname === '/api/rules' && req.method === 'POST') {
    const s=await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401);
    const b=await req.json().catch(()=>({})); const id=b.id||uid('rule');
    const title=String(b.title||'').trim(), body=String(b.body||'').trim();
    if(!title||!body) return json({error:'Rule title and body are required'},400);
    if(b.id) await env.DB.prepare('UPDATE rules SET title=?,body=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(title,body,id).run();
    else await env.DB.prepare('INSERT INTO rules(id,title,body) VALUES(?,?,?)').bind(id,title,body).run();
    await audit(env,s.email,b.id?'update':'create','rule',id); return json({ok:true,id});
  }
  if (url.pathname.startsWith('/api/rules/') && req.method === 'DELETE') {
    const s=await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401);
    const id=url.pathname.split('/').pop();
    await env.DB.prepare('DELETE FROM rules WHERE id=?').bind(id).run();
    await audit(env,s.email,'delete','rule',id); return json({ok:true});
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
  if (url.pathname === '/api/org-fund' && req.method === 'POST') {
    const s=await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401);
    const b=await req.json().catch(()=>({})); const amount=Number(b.amount);
    const categories=['যাকাত','ফিতরা','স্বেচ্ছা দান','জরিমানা','অন্যান্য'];
    const donorName=String(b.donorName||'').trim();
    if(!/^\d{4}-\d{2}-\d{2}$/.test(b.date)||!Number.isFinite(amount)||amount<=0||!['income','expense'].includes(b.kind)||!categories.includes(String(b.category||''))) return json({error:'Invalid organizational fund transaction'},400);
    if(b.kind==='income' && !donorName) return json({error:'জমাদাতার নাম দিন।'},400);
    const id=uid('of');
    await env.DB.prepare('INSERT INTO organizational_fund_transactions(id,tx_date,kind,category,amount,donor_name,description) VALUES(?,?,?,?,?,?,?)').bind(id,b.date,b.kind,String(b.category),amount,donorName,String(b.description||'').trim()).run();
    await audit(env,s.email,'create','organizational_fund',id); return json({ok:true,id});
  }
  if (url.pathname.startsWith('/api/org-fund/') && req.method === 'DELETE') {
    const s=await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401); const id=url.pathname.split('/').pop();
    await env.DB.prepare('DELETE FROM organizational_fund_transactions WHERE id=?').bind(id).run(); await audit(env,s.email,'delete','organizational_fund',id); return json({ok:true});
  }
  return json({error:'Not found'},404);
}

export default { async fetch(req,env,ctx) {
  const url=new URL(req.url);
  if(url.pathname.startsWith('/api/')) { try { return await route(req,env); } catch(e) { return json({error:'Server error',detail:String(e?.message||e)},500); } }
  return env.ASSETS.fetch(req);
}};
