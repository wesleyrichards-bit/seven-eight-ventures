// Password gate for Seven Eight Ventures (Vercel Routing Middleware).
// The password is NOT stored here: set SITE_PASSWORD in
// Vercel → Project → Settings → Environment Variables, then redeploy.
// If SITE_PASSWORD is missing, the site stays locked.

export const config = {
  matcher: ['/((?!favicon\\.ico|favicon-48\\.png|favicon-192\\.png|apple-touch-icon\\.png).*)'],
};

const COOKIE = 'sev_access';
const MAX_AGE = 60 * 60 * 24 * 30; // 30 days

async function token(secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode('seven-eight-ventures-access'));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function readCookie(req, name) {
  const raw = req.headers.get('cookie') || '';
  for (const part of raw.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export default async function middleware(req) {
  const secret = process.env.SITE_PASSWORD;
  const url = new URL(req.url);
  const expected = secret ? await token(secret) : null;

  // Handle login form submission
  if (url.pathname === '/__login' && req.method === 'POST') {
    const form = await req.formData();
    const pw = String(form.get('password') || '');
    if (secret && safeEqual(pw, secret)) {
      return new Response(null, {
        status: 303,
        headers: {
          Location: '/',
          'Set-Cookie': `${COOKIE}=${expected}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Lax`,
        },
      });
    }
    return loginPage(true);
  }

  // Already signed in: let the request through
  if (expected && safeEqual(readCookie(req, COOKIE) || '', expected)) return;

  return loginPage(false);
}

function loginPage(error) {
  const html = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Seven Eight Ventures</title>
<link rel="icon" href="/favicon.ico" sizes="any">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@400;500&family=Inter:wght@300;400;500&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{min-height:100vh;background:#08121f;color:#f3eee6;font-family:Inter,system-ui,sans-serif;font-weight:300;display:flex;flex-direction:column}
header{padding:32px 48px;border-bottom:1px solid rgba(255,255,255,.06)}
.logo{font-family:"Cormorant Garamond",Georgia,serif;font-size:20px;letter-spacing:.32em}
main{flex:1;display:flex;align-items:center;justify-content:center;padding:48px 24px}
.box{width:100%;max-width:440px}
.eyebrow{font-size:11.2px;letter-spacing:.32em;text-transform:uppercase;color:#b8955a}
h1{font-family:"Cormorant Garamond",Georgia,serif;font-weight:400;font-size:40px;line-height:1.15;margin:22px 0 14px}
p{color:#a7adb7;font-size:15px;line-height:1.6}
.rule{width:56px;height:1px;background:#b8955a;margin:32px 0}
label{display:block;font-size:11px;letter-spacing:.2em;text-transform:uppercase;color:#a7adb7;margin-bottom:10px}
input{width:100%;background:transparent;border:0;border-bottom:1px solid rgba(243,238,230,.25);color:#f3eee6;font:inherit;font-size:17px;padding:10px 0;outline:none;transition:border-color .2s}
input:focus{border-color:#c9a96e}
button{margin-top:30px;background:none;border:0;color:#c9a96e;font:inherit;font-size:17px;font-weight:400;cursor:pointer;display:inline-flex;gap:12px;align-items:center;padding:0;transition:gap .2s}
button:hover{gap:18px}
.err{color:#d9a28b;font-size:14px;margin-top:14px}
footer{padding:24px 48px;font-size:12px;color:#7d8592;border-top:1px solid rgba(255,255,255,.06)}
@media(max-width:720px){header,footer{padding-left:24px;padding-right:24px}.logo{font-size:16px}}
</style></head>
<body>
<header><div class="logo">SEVEN EIGHT VENTURES</div></header>
<main><div class="box">
  <div class="eyebrow">Private Opportunities</div>
  <h1>For eligible clients only.</h1>
  <p>Please enter the access password to continue.</p>
  <div class="rule"></div>
  <form method="POST" action="/__login">
    <label for="pw">Password</label>
    <input id="pw" name="password" type="password" autocomplete="current-password" required autofocus>
    ${error ? '<div class="err">That password was not recognised. Please try again.</div>' : ''}
    <button type="submit">Enter <span>&rarr;</span></button>
  </form>
  <p style="margin-top:40px;font-size:13px">Need access? <span style="color:#c9a96e">enquiries@seveneightasset.com</span></p>
</div></main>
<footer>Opportunities are available to eligible investors only. Capital is at risk.</footer>
</body></html>`;
  return new Response(html, {
    status: error ? 401 : 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex' },
  });
}
