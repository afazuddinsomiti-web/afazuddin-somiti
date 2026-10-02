const COOKIE = 'somiti_session';
const SESSION_DAYS = 7;
const ADMIN_EMAIL_DEFAULT = 'afazuddinsomiti@gmail.com';

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', ...headers }
  });
}
function uid(prefix='id') { return `${prefix}_${crypto.randomUUID()}`; }
function bytesToHex(buf) { return [...new Uint8Array(buf)].map(b=>b.toString(16).padStart(2,'0')).join(''); }
async function sha256(text) { return bytesToHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))); }
async function hashPassword(password, salt = crypto.randomUUID()) {
  const data = new TextEncoder().encode(`${salt}:${password}`);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return `${salt}$${bytesToHex(digest)}`;
}
async function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || '').split('$');
  if (!salt || !hash) return false;
  const candidate = await hashPassword(password, salt);
  return candidate === stored;
}
function cookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
async function session(req, env) {
  const raw = req.headers.get('Cookie') || '';
  const match = raw.match(new RegExp(`${COOKIE}=([^;]+)`));
  if (!match) return null;
  const tokenHash = await sha256(match[1]);
  const row = await env.DB.prepare('SELECT email, expires_at FROM sessions WHERE token_hash=? AND expires_at>?').bind(tokenHash, Date.now()).first();
  return row || null;
}
function corsHeaders() { return { 'cache-control': 'no-store' }; }
async function ensureAdmin(env) {
  const email = env.ADMIN_EMAIL || ADMIN_EMAIL_DEFAULT;
  const existing = await env.DB.prepare('SELECT email FROM admins WHERE email=?').bind(email).first();
  if (existing) return;
  const initial = env.ADMIN_INITIAL_PASSWORD;
  if (!initial) throw new Error('ADMIN_INITIAL_PASSWORD secret is not configured');
  const password_hash = await hashPassword(initial);
  await env.DB.prepare('INSERT INTO admins(email,password_hash,must_change_password) VALUES(?,?,1)').bind(email,password_hash).run();
}
async function requireAdmin(req, env) {
  const s = await session(req, env);
  if (!s) return null;
  return s;
}
async function audit(env, email, action, entity='', entityId='') {
  await env.DB.prepare('INSERT INTO audit_log(id,email,action,entity,entity_id) VALUES(?,?,?,?,?)').bind(uid('audit'),email,action,entity,entityId).run();
}
function money(n){ return Number(n||0); }
function monthNow(){ return new Date().toISOString().slice(0,7); }
function currentDay(){ return new Date().getDate(); }
async function state(env) {
  const members = await env.DB.prepare('SELECT id,member_no AS no,name,position,phone,shares,join_date AS joinDate FROM members WHERE active=1 ORDER BY member_no').all();
  const payments = await env.DB.prepare('SELECT id,member_id AS memberId,month,amount,payment_date AS date,notes FROM payments ORDER BY payment_date DESC').all();
  const fund = await env.DB.prepare("SELECT id,tx_date AS date,kind,amount,category,description,member_id AS memberId,month FROM fund_transactions ORDER BY tx_date DESC").all();
  return { members: members.results || [], payments: payments.results || [], fund: fund.results || [], month: monthNow(), day: currentDay() };
}
async function route(req, env) {
  await ensureAdmin(env);
  const url = new URL(req.url);
  if (url.pathname === '/api/state' && req.method === 'GET') return json(await state(env), 200, corsHeaders());
  if (url.pathname === '/api/me' && req.method === 'GET') {
    const s = await session(req, env);
    if (!s) return json({ authenticated:false });
    const admin = await env.DB.prepare('SELECT email,must_change_password AS mustChangePassword FROM admins WHERE email=?').bind(s.email).first();
    return json({ authenticated:true, ...admin });
  }
  if (url.pathname === '/api/login' && req.method === 'POST') {
    const body = await req.json().catch(()=>({}));
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const admin = await env.DB.prepare('SELECT email,password_hash,must_change_password AS mustChangePassword FROM admins WHERE lower(email)=?').bind(email).first();
    if (!admin || !(await verifyPassword(password, admin.password_hash))) return json({error:'Invalid login'},401);
    const token = `${crypto.randomUUID()}-${crypto.randomUUID()}`;
    const tokenHash = await sha256(token);
    const expires = Date.now() + SESSION_DAYS*24*60*60*1000;
    await env.DB.prepare('INSERT INTO sessions(token_hash,email,expires_at) VALUES(?,?,?)').bind(tokenHash,admin.email,expires).run();
    await audit(env,admin.email,'login');
    return json({ok:true,email:admin.email,mustChangePassword:!!admin.mustChangePassword},200,{'Set-Cookie':cookie(COOKIE,token,SESSION_DAYS*24*60*60)});
  }
  if (url.pathname === '/api/logout' && req.method === 'POST') {
    const s = await session(req, env);
    if (s) await env.DB.prepare('DELETE FROM sessions WHERE email=?').bind(s.email).run();
    return json({ok:true},200,{'Set-Cookie':cookie(COOKIE,'',0)});
  }
  if (url.pathname === '/api/change-password' && req.method === 'POST') {
    const s = await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401);
    const body=await req.json().catch(()=>({})); const p=String(body.password||'');
    if(p.length<12) return json({error:'Password must be at least 12 characters'},400);
    const h=await hashPassword(p);
    await env.DB.prepare('UPDATE admins SET password_hash=?,must_change_password=0,updated_at=CURRENT_TIMESTAMP WHERE email=?').bind(h,s.email).run();
    await audit(env,s.email,'change_password','admin',s.email);
    return json({ok:true});
  }
  if (req.method === 'POST' && url.pathname === '/api/members') {
    const s=await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401);
    const b=await req.json(); const id=b.id||uid('m');
    const shares=Number(b.shares), memberNo=Number(b.no); if(!b.name || !Number.isInteger(shares) || shares<1 || !Number.isInteger(memberNo) || memberNo<1) return json({error:'Invalid member data'},400);
    if(b.id) await env.DB.prepare('UPDATE members SET member_no=?,name=?,position=?,phone=?,shares=?,join_date=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').bind(memberNo,b.name,b.position||'',b.phone||'',shares,b.join||'',id).run();
    else await env.DB.prepare('INSERT INTO members(id,member_no,name,position,phone,shares,join_date) VALUES(?,?,?,?,?,?,?)').bind(id,memberNo,b.name,b.position||'',b.phone||'',shares,b.join||'').run();
    await audit(env,s.email,b.id?'update':'create','member',id); return json({ok:true,id});
  }
  if (req.method === 'POST' && url.pathname === '/api/payments') {
    const s=await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401);
    const b=await req.json(); const id=uid('p');
    if(!b.memberId||!b.month||Number(b.amount)<=0||!b.date) return json({error:'Invalid payment'},400);
    await env.DB.prepare('INSERT INTO payments(id,member_id,month,amount,payment_date,notes) VALUES(?,?,?,?,?,?)').bind(id,b.memberId,b.month,Number(b.amount),b.date,b.notes||'').run();
    const fid=uid('f'); await env.DB.prepare('INSERT INTO fund_transactions(id,tx_date,kind,amount,category,description,member_id,month) VALUES(?,?,?,?,?,?,?,?)').bind(fid,b.date,'income',Number(b.amount),'Monthly Share','Member contribution',b.memberId,b.month).run();
    await audit(env,s.email,'create','payment',id); return json({ok:true,id});
  }
  if (req.method === 'POST' && url.pathname === '/api/fund') {
    const s=await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401);
    const b=await req.json(); const id=uid('f'); if(!b.date||Number(b.amount)<=0||!['income','investment','expense'].includes(b.kind)) return json({error:'Invalid fund transaction'},400);
    await env.DB.prepare('INSERT INTO fund_transactions(id,tx_date,kind,amount,category,description,member_id,month) VALUES(?,?,?,?,?,?,?,?)').bind(id,b.date,b.kind,Number(b.amount),b.category||'',b.description||'',b.memberId||null,b.month||null).run();
    await audit(env,s.email,'create','fund',id); return json({ok:true,id});
  }
  if (req.method === 'DELETE' && url.pathname.startsWith('/api/fund/')) {
    const s=await requireAdmin(req,env); if(!s) return json({error:'Unauthorized'},401); const id=url.pathname.split('/').pop();
    await env.DB.prepare('DELETE FROM fund_transactions WHERE id=?').bind(id).run(); await audit(env,s.email,'delete','fund',id); return json({ok:true});
  }
  return json({error:'Not found'},404);
}
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    if (url.pathname.startsWith('/api/')) {
      try { return await route(req, env); } catch (e) { return json({error:'Server error', detail:String(e?.message||e)},500); }
    }
    return env.ASSETS.fetch(req);
  }
};
