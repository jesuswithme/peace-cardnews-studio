// 평화로운마음 카드뉴스 스튜디오 - 로컬 서버
// "Sign in with ChatGPT" (ChatGPT plan usage, OSS/로컬 앱용 공식 플로우)로 내 ChatGPT 구독을 연결합니다.
// 외부 패키지 없이 Node 18+ 기본 모듈만 사용합니다.  실행: node server.mjs
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { exec } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const APP_NAME = 'PeaceMind CardNews Studio';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const CONF_DIR = path.join(os.homedir(), '.config', 'peace-cardnews');
const CRED_FILE = path.join(CONF_DIR, 'credentials.json');
const HOST_FILE = path.join(CONF_DIR, 'host.json');
const ISSUER = 'https://auth.openai.com';
const AUTHORIZE = 'https://auth.openai.com/api/accounts/authorize';
const TOKEN = 'https://auth.openai.com/api/accounts/oauth/token';
const REVOKE = 'https://auth.openai.com/api/accounts/oauth/revoke';
const JWKS_URL = 'https://auth.openai.com/.well-known/jwks.json';
const RESOURCE = 'https://api.openai.com/v1';
const SCOPES = 'openid profile email offline_access resource.invoke chatgpt.tokens.use.direct';
const USAGE_URL = 'https://chatgpt.com/settings/usage';

let PORT = Number(process.env.PORT) || 1477;
const redirectUri = () => `http://127.0.0.1:${PORT}/auth/callback`;

/* ---------- 파일 저장 (토큰은 브라우저가 아닌 로컬 파일에만) ---------- */
fs.mkdirSync(CONF_DIR, { recursive: true });
function readJSON(f) { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } }
function writeJSON(f, obj) { const tmp = f + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), { mode: 0o600 }); fs.renameSync(tmp, f); try { fs.chmodSync(f, 0o600); } catch {} }
function hostId() {
  let h = readJSON(HOST_FILE);
  if (!h?.ext_agent_host_id) { h = { ext_agent_host_id: `urn:uuid:${crypto.randomUUID()}`, created_at: new Date().toISOString() }; writeJSON(HOST_FILE, h); }
  return h.ext_agent_host_id;
}
const loadCreds = () => readJSON(CRED_FILE);
const saveCreds = c => writeJSON(CRED_FILE, c);

/* ---------- 유틸 ---------- */
const b64url = buf => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const rand = (n = 32) => b64url(crypto.randomBytes(n));
const pending = new Map(); // state -> {verifier, nonce, clientId, isNew, created}
function send(res, status, body, type = 'application/json; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}
function page(res, title, msg, ok = false) {
  send(res, ok ? 200 : 400, `<!doctype html><meta charset="utf-8"><title>${title}</title><body style="font-family:sans-serif;background:#f3f0e8;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="background:#fff;padding:32px 40px;border-radius:18px;max-width:520px;box-shadow:0 10px 30px rgba(0,0,0,.08)"><h2 style="margin-top:0">${title}</h2><p style="line-height:1.6;color:#444">${msg}</p><a href="/" style="display:inline-block;margin-top:10px;background:#111;color:#fff;padding:10px 18px;border-radius:10px;text-decoration:none">스튜디오로 돌아가기</a></div></body>`, 'text/html; charset=utf-8');
}
async function readBody(req) { let d = ''; for await (const c of req) { d += c; if (d.length > 2e6) throw new Error('too large'); } return d ? JSON.parse(d) : {}; }
async function postForm(url, params) {
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: new URLSearchParams(params).toString() });
  const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch {}
  return { ok: r.ok, status: r.status, json, text };
}

/* ---------- ID 토큰 검증 (RS256, OpenAI JWKS) ---------- */
let jwksCache = { at: 0, keys: [] };
async function getJwk(kid) {
  const find = () => jwksCache.keys.find(k => k.kid === kid);
  if (!find() || Date.now() - jwksCache.at > 3600e3) { const r = await fetch(JWKS_URL); jwksCache = { at: Date.now(), keys: (await r.json()).keys || [] }; }
  return find();
}
async function verifyIdToken(idToken, clientId, nonce) {
  const [h, p, s] = String(idToken).split('.');
  if (!h || !p || !s) throw new Error('ID 토큰 형식 오류');
  const header = JSON.parse(Buffer.from(h, 'base64url').toString());
  if (header.alg !== 'RS256') throw new Error('지원하지 않는 서명 알고리즘');
  const jwk = await getJwk(header.kid); if (!jwk) throw new Error('서명 키를 찾지 못함');
  const okSig = crypto.verify('RSA-SHA256', Buffer.from(`${h}.${p}`), crypto.createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(s, 'base64url'));
  if (!okSig) throw new Error('ID 토큰 서명 검증 실패');
  const c = JSON.parse(Buffer.from(p, 'base64url').toString());
  const now = Math.floor(Date.now() / 1000);
  if (c.iss !== ISSUER) throw new Error('issuer 불일치');
  const aud = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!aud.includes(clientId)) throw new Error('audience 불일치');
  if (!c.exp || c.exp < now - 5) throw new Error('ID 토큰 만료');
  if (c.nonce !== nonce) throw new Error('nonce 불일치');
  if (typeof c.sub !== 'string' || !c.sub) throw new Error('subject 없음');
  return c;
}

/* ---------- 토큰 갱신 (직렬화) ---------- */
let refreshing = null;
const REFRESH_DEAD = ['invalid_grant', 'invalid_refresh_token', 'token_expired', 'refresh_token_expired', 'refresh_token_invalidated', 'refresh_token_reused'];
async function accessToken() {
  const c = loadCreds();
  if (!c?.access_token) { const e = new Error('ChatGPT에 연결되어 있지 않아요'); e.status = 401; e.code = 'not_connected'; throw e; }
  if (!c.scopes?.includes('chatgpt.tokens.use.direct')) { const e = new Error('ChatGPT 구독 사용 권한이 허용되지 않았어요'); e.status = 403; e.code = 'plan_not_enabled'; throw e; }
  if (Date.now() < (c.expires_at || 0) - 120e3) return c.access_token;
  if (!refreshing) refreshing = (async () => {
    const r = await postForm(TOKEN, { grant_type: 'refresh_token', client_id: c.client_id, refresh_token: c.refresh_token, resource: RESOURCE });
    if (!r.ok) {
      const code = r.json?.error?.code || r.json?.error || r.json?.code || '';
      if (REFRESH_DEAD.includes(code)) { saveCreds({ ...c, access_token: null, refresh_token: null, needs_reauth: true }); }
      const e = new Error(`토큰 갱신 실패 (${code || r.status}). 다시 연결해 주세요`); e.status = 401; e.code = 'refresh_failed'; throw e;
    }
    const t = r.json;
    const scopes = String(t.scope || c.scopes.join(' ')).split(/\s+/).filter(Boolean);
    saveCreds({ ...c, access_token: t.access_token, refresh_token: t.refresh_token || c.refresh_token, id_token: t.id_token || c.id_token, expires_in: t.expires_in, expires_at: Date.now() + (t.expires_in || 3600) * 1000, scopes, saved_at: new Date().toISOString(), needs_reauth: false });
    return t.access_token;
  })().finally(() => { refreshing = null; });
  return refreshing;
}

/* ---------- Responses API (store:false, stream:true) ---------- */
const ERR_KO = {
  subscription_sharing_usage_limit_exceeded: 'ChatGPT 구독 사용량 한도에 도달했어요. 사용량 관리에서 확인해 주세요.',
  subscription_sharing_user_not_eligible: '이 계정(요금제)에서는 앱에서 구독 사용이 지원되지 않아요. Plus/Pro/Go 요금제가 필요해요.',
  subscription_sharing_usage_unavailable: '사용량 확인이 일시적으로 안 돼요. 잠시 후 다시 시도해 주세요.',
  subscription_sharing_user_unavailable: '계정 정보를 일시적으로 확인할 수 없어요. 잠시 후 다시 시도해 주세요.',
  subscription_sharing_invalid_user: '구독 계정 확인에 실패했어요. ChatGPT에 다시 연결해 주세요.',
  subscription_sharing_unsupported_capability: '선택한 모델/옵션이 구독 연동에서 지원되지 않아요. 다른 모델을 골라 주세요.',
};
async function respond(model, instructions, prompt) {
  const token = await accessToken();
  const r = await fetch(`${RESOURCE}/responses`, {
    method: 'POST', headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json', Accept: 'text/event-stream' },
    body: JSON.stringify({ model, instructions, input: [{ role: 'user', content: prompt }], store: false, stream: true }),
  });
  const reqId = r.headers.get('x-request-id') || '';
  if (!r.ok) {
    const text = await r.text(); let j = null; try { j = JSON.parse(text); } catch {}
    const code = j?.error?.code || ''; const detail = j?.error?.message || j?.detail || text.slice(0, 300);
    const e = new Error(ERR_KO[code] || `ChatGPT 요청 실패 (${r.status}) ${detail}`); e.status = r.status; e.code = code; e.reqId = reqId; throw e;
  }
  const reader = r.body.getReader(); const dec = new TextDecoder();
  let buf = '', out = '', completed = false, failed = null;
  for (;;) {
    const { value, done } = await reader.read(); if (done) break;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim(); buf = buf.slice(i + 1);
      if (!line.startsWith('data:')) continue;
      const data = line.slice(5).trim(); if (!data || data === '[DONE]') continue;
      let ev; try { ev = JSON.parse(data); } catch { continue; }
      if (ev.type === 'response.output_text.delta') out += ev.delta || '';
      else if (ev.type === 'response.completed') { completed = true; if (!out) out = extractText(ev.response); }
      else if (ev.type === 'response.failed') failed = ev.response?.error || { code: 'response_failed' };
      else if (ev.type === 'response.incomplete') failed = { code: 'response_incomplete', message: ev.response?.incomplete_details?.reason };
      else if (ev.type === 'error') failed = ev.error || ev;
    }
  }
  if (failed) { const e = new Error(ERR_KO[failed.code] || `ChatGPT 응답 실패: ${failed.code || ''} ${failed.message || ''}`); e.status = failed.code === 'subscription_sharing_usage_limit_exceeded' ? 429 : 502; e.code = failed.code; e.reqId = reqId; throw e; }
  if (!completed) { const e = new Error('응답 스트림이 완료되지 않았어요. 다시 시도해 주세요'); e.status = 502; e.code = 'stream_incomplete'; throw e; }
  return out;
}
function extractText(resp) { try { return resp.output.flatMap(o => o.content || []).filter(c => c.type === 'output_text').map(c => c.text).join(''); } catch { return ''; } }

let modelCache = { at: 0, list: [] };
async function models() {
  if (Date.now() - modelCache.at < 600e3 && modelCache.list.length) return modelCache.list;
  const token = await accessToken();
  const r = await fetch(`${RESOURCE}/models`, { headers: { Authorization: `Bearer ${token}` } });
  if (!r.ok) throw Object.assign(new Error(`모델 목록 실패 (${r.status})`), { status: r.status });
  const j = await r.json();
  const arr = (j.models || j.data || []).filter(m => !m.visibility || m.visibility === 'list').map(m => ({ slug: m.slug || m.id, name: m.display_name || m.slug || m.id }));
  modelCache = { at: Date.now(), list: arr }; return arr;
}

/* ---------- HTTP 서버 ---------- */
const server = http.createServer(async (req, res) => {
  try {
    // DNS 리바인딩 방지: 로컬 호스트 이름만 허용
    const host = String(req.headers.host || '');
    if (!/^(127\.0\.0\.1|localhost):\d+$/.test(host)) return send(res, 403, { error: 'forbidden host' });
    const url = new URL(req.url, `http://${host}`);
    const origin = req.headers.origin;
    if (req.method === 'POST' && origin && !/^http:\/\/(127\.0\.0\.1|localhost):\d+$/.test(origin)) return send(res, 403, { error: 'forbidden origin' });

    // 정적 파일
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      if (host.startsWith('localhost')) { res.writeHead(302, { Location: `http://127.0.0.1:${PORT}/` }); return res.end(); }
      return send(res, 200, fs.readFileSync(path.join(HERE, 'index.html')), 'text/html; charset=utf-8');
    }

    // 로그인 시작
    if (url.pathname === '/auth/login') {
      const c = loadCreds();
      const reuse = c?.client_id && !url.searchParams.has('new');
      const clientId = reuse ? c.client_id : 'dynamic_agent_client';
      const verifier = rand(48), state = rand(24), nonce = rand(24);
      const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
      pending.set(state, { verifier, nonce, clientId, isNew: !reuse, created: Date.now() });
      for (const [k, v] of pending) if (Date.now() - v.created > 15 * 60e3) pending.delete(k);
      const p = new URLSearchParams({ client_id: clientId, response_type: 'code', redirect_uri: redirectUri(), scope: SCOPES, resource: RESOURCE, state, nonce, code_challenge_method: 'S256', code_challenge: challenge, ext_agent_host_id: hostId() });
      if (!reuse) p.set('agent_name_hint', APP_NAME);
      else { if (c.id_token && !c.signed_out) p.set('id_token_hint', c.id_token); if (c.email) p.set('login_hint', c.email); }
      if (url.searchParams.has('reconsent')) p.set('prompt', 'consent');
      res.writeHead(302, { Location: `${AUTHORIZE}?${p}` }); return res.end();
    }

    // 콜백
    if (url.pathname === '/auth/callback') {
      const q = url.searchParams; const st = q.get('state'); const pend = st && pending.get(st);
      if (!pend) return page(res, '연결 실패', '로그인 요청이 만료되었거나 올바르지 않아요. 다시 시도해 주세요.');
      pending.delete(st);
      if (q.get('error')) {
        const denied = q.get('error') === 'access_denied';
        return page(res, denied ? '연결이 취소되었어요' : '연결 실패', denied ? 'ChatGPT 구독 사용을 허용하지 않았어요. 스튜디오의 무료 AI는 계속 쓸 수 있고, 언제든 다시 연결할 수 있어요.' : `오류: ${q.get('error')} ${q.get('error_description') || ''}`);
      }
      let clientId = pend.clientId;
      if (pend.isNew) { clientId = q.get('client_id'); if (!clientId || clientId === 'dynamic_agent_client') return page(res, '연결 실패', '앱 등록이 완료되지 않았어요(client_id 없음). 다시 시도해 주세요.'); }
      else if (q.get('client_id') && q.get('client_id') !== pend.clientId) return page(res, '연결 실패', '다른 앱 등록 정보가 돌아왔어요. 보안을 위해 중단했어요.');
      const t = await postForm(TOKEN, { grant_type: 'authorization_code', client_id: clientId, code: q.get('code'), code_verifier: pend.verifier, redirect_uri: redirectUri(), resource: RESOURCE });
      if (!t.ok) return page(res, '연결 실패', `토큰 교환 실패 (${t.status}). 다시 시도해 주세요.`);
      const tok = t.json;
      const claims = await verifyIdToken(tok.id_token, clientId, pend.nonce);
      const prev = loadCreds();
      if (!pend.isNew && prev?.subject && prev.subject !== claims.sub) return page(res, '연결 실패', '저장된 계정과 다른 ChatGPT 계정이에요. 같은 계정으로 로그인해 주세요.');
      const scopes = String(tok.scope || q.get('scope') || '').split(/[\s+]+/).filter(Boolean);
      saveCreds({
        email: claims.email || '', name: claims.name || '', issuer: ISSUER, subject: claims.sub, client_id: clientId, ext_agent_host_id: hostId(),
        id_token: tok.id_token, access_token: tok.access_token, refresh_token: tok.refresh_token, token_type: tok.token_type || 'Bearer',
        expires_in: tok.expires_in, expires_at: Date.now() + (tok.expires_in || 3600) * 1000, scopes, saved_at: new Date().toISOString(),
        welcomed: prev?.subject === claims.sub ? !!prev.welcomed : false, model: prev?.model || '', signed_out: false,
      });
      modelCache = { at: 0, list: [] };
      res.writeHead(302, { Location: '/?chatgpt=connected' }); return res.end();
    }

    // 로그아웃 (리프레시 토큰 해지)
    if (url.pathname === '/auth/logout' && req.method === 'POST') {
      const c = loadCreds(); let revoked = false;
      if (c?.refresh_token) { for (let a = 0; a < 3 && !revoked; a++) { try { const r = await postForm(REVOKE, { token: c.refresh_token, token_type_hint: 'refresh_token', client_id: c.client_id }); revoked = r.ok; if (r.status < 500) break; } catch {} await new Promise(r => setTimeout(r, 800 * (a + 1))); } }
      if (c) saveCreds({ ...c, access_token: null, refresh_token: null, id_token: null, signed_out: true });
      return send(res, 200, { ok: true, revoked });
    }

    if (url.pathname === '/api/status') {
      const c = loadCreds();
      return send(res, 200, { server: true, connected: !!c?.access_token, email: c?.email || '', name: c?.name || '', planEnabled: !!c?.scopes?.includes('chatgpt.tokens.use.direct'), welcomed: !!c?.welcomed, model: c?.model || '', needsReauth: !!c?.needs_reauth, registered: !!c?.client_id, usageUrl: USAGE_URL });
    }
    if (url.pathname === '/api/welcomed' && req.method === 'POST') { const c = loadCreds(); if (c) saveCreds({ ...c, welcomed: true }); return send(res, 200, { ok: true }); }
    if (url.pathname === '/api/model' && req.method === 'POST') { const b = await readBody(req); const c = loadCreds(); if (c) saveCreds({ ...c, model: String(b.model || '') }); return send(res, 200, { ok: true }); }
    if (url.pathname === '/api/models') return send(res, 200, { models: await models() });
    if (url.pathname === '/api/generate' && req.method === 'POST') {
      const b = await readBody(req);
      let model = b.model || loadCreds()?.model;
      if (!model) model = (await models())[0]?.slug;
      if (!model) return send(res, 400, { error: '사용 가능한 모델이 없어요' });
      const text = await respond(model, b.instructions || 'You are a helpful assistant.', String(b.prompt || ''));
      return send(res, 200, { text, model });
    }
    send(res, 404, { error: 'not found' });
  } catch (e) {
    console.error('[오류]', e.code || '', e.message, e.reqId ? `(request-id ${e.reqId})` : '');
    if (!res.headersSent) send(res, e.status && e.status >= 400 ? e.status : 500, { error: e.message, code: e.code || '', requestId: e.reqId || '', usageUrl: USAGE_URL });
  }
});

function listen(port, tries = 0) {
  PORT = port;
  server.once('error', err => { if (err.code === 'EADDRINUSE' && tries < 10) listen(port + 1, tries + 1); else { console.error(err); process.exit(1); } });
  server.listen(port, '127.0.0.1', () => {
    const u = `http://127.0.0.1:${PORT}/`;
    console.log(`\n  평화로운마음 카드뉴스 스튜디오 실행 중 → ${u}\n  (이 창을 닫으면 종료됩니다)\n`);
    if (!process.env.NO_OPEN) { const cmd = process.platform === 'win32' ? `start "" "${u}"` : process.platform === 'darwin' ? `open "${u}"` : `xdg-open "${u}"`; exec(cmd); }
  });
}
listen(PORT);
