import asyncio
import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict
from urllib.parse import urlparse, urlencode, quote

import redis.asyncio as redis
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.responses import StreamingResponse
from ircrobots import Bot as BaseBot, Server as BaseServer, ConnectionParams
from irctokens import build
import uvicorn
import ssl
import sys
import logging
import jwt

# --- Configuration ---
IRC_SERVER = os.getenv("IRC_SERVER", "irc")
IRC_PORT = int(os.getenv("IRC_PORT", "6697"))
IRC_NICK = os.getenv("IRC_NICK", "kircfwdauth")
IRC_CHANNELS = os.getenv("IRC_CHANNELS", "") # Bot's own channels, not for auth
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")
COOKIE_TTL = int(os.getenv("COOKIE_TTL", "86400"))
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-to-a-real-secret-in-production")
INSECURE = JWT_SECRET_KEY.startswith("change-this")
if INSECURE:
    print("Using default JWT, running in Insecure mode.")
BASE_CSS = """
body {
    font-family: -apple-system, BlinkMacSystemFont, 'segoe ui', helvetica, arial, sans-serif;
    background: #1a1a1a;
    color: #f0f0f0;
    margin: 0;
    padding: 20px;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
}
.container {
    background: #2c2c2c;
    max-width: 400px;
    width: 100%;
    padding: 40px;
    border-radius: 12px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    text-align: center;
}
h2 {
    color: #ff69b4;
    font-weight: 300;
    margin-bottom: 15px;
    font-size: 28px;
}
p {
    color: #a9a9a9;
    line-height: 1.4;
    margin: 15px 0;
}
.accent-box {
    background: #3a3a3a;
    padding: 15px;
    font-family: monospace;
    font-size: 18px;
    border-radius: 5px;
    margin: 15px 0;
    color: #e0e0e0;
}
.copy-command {
    cursor: pointer;
    display: inline-block;
    padding: 5px;
    border-radius: 4px;
}
.copy-command:hover {
    background-color: #4a4a4a;
}
.status {
    margin-top: 20px;
    font-weight: bold;
    min-height: 1.2em; /* Prevents layout shift when text appears */
}
.status-success {
    color: #50fa7b; /* Bright Green */
}
.status-error {
    color: #ff5555; /* Bright Red */
}
"""

def simple_response(title: str, content: str, status_code: int = 200) -> HTMLResponse:
    """Create an HTML response with consistent styling"""
    html = f"""<!DOCTYPE html>
<html><head>
<title>{title}</title>
<style>{BASE_CSS}</style>
</head>
<body>
<div class="container">
{content}
</div>
</body></html>"""
    return HTMLResponse(html, status_code=status_code)


# --- Logging ---
log = logging.getLogger("irc")
log.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
log.addHandler(handler)

# --- Globals ---
app = FastAPI()
redis_client = None
sse_queues: Dict[str, asyncio.Queue] = {}


async def get_session_from_cookie(request: Request, canonical_domain: str):
    """Finds a valid auth token from cookies for a given canonical domain."""
    for cookie_name, token in request.cookies.items():
        if cookie_name.startswith("irc_auth_"):
            if await redis_client.exists(f"session:{canonical_domain}:{token}"):
                log.debug(f"Found valid session token in cookie '{cookie_name}' for domain '{canonical_domain}'")
                return await redis_client.hgetall(f"session:{canonical_domain}:{token}")
    return None


class AuthServer(BaseServer):
    async def line_read(self, line):
        if line.command == "PRIVMSG" and line.params and line.params[0] == self.nickname:
            sender = line.hostmask.nickname
            message = line.params[1].strip()
            await self.handle_challenge(sender, message)

    async def handle_challenge(self, nick: str, verify_token: str):
        challenge_key = f"challenge:{verify_token}"
        challenge_data = await redis_client.hgetall(challenge_key)
        if not challenge_data:
            return

        canonical_domain = challenge_data[b'canonical_domain'].decode()
        channels = challenge_data[b'channels'].decode().split(',')

        has_access = False
        for channel_name in channels:
            channel = self.channels.get(channel_name)
            if channel and nick.lower() in [u.lower() for u in channel.users]:
                has_access = True
                break

        queue = sse_queues.get(verify_token)
        if has_access:
            auth_token = secrets.token_urlsafe(32)
            session_key = f"session:{canonical_domain}:{auth_token}"
            await redis_client.hset(session_key, mapping={'nick': nick, 'created': str(int(datetime.now(timezone.utc).timestamp()))})
            await redis_client.expire(session_key, COOKIE_TTL)

            result_key = f"result:{verify_token}"
            await redis_client.hset(result_key, mapping={
                'status': 'success',
                'auth_token': auth_token,
                'nick': nick
            })
            await redis_client.expire(result_key, 300)

            log.info(f"Access granted for {nick} to {canonical_domain}")
            if queue:
                await queue.put("event: success\ndata: access granted!\n\n")
        else:
            result_key = f"result:{verify_token}"
            await redis_client.hset(result_key, mapping={
                'status': 'error',
                'message': 'oh no... you\'re not in the right channels,,,',
            })
            await redis_client.expire(result_key, 300)

            log.warning(f"Access denied for {nick} to {canonical_domain}")
            if queue:
                await queue.put("event: error\ndata: oh no... you're not in the right channels,,,\n\n")


class AuthBot(BaseBot):
    def create_server(self, name: str):
        return AuthServer(self, name)


irc_bot = AuthBot()


async def connect_irc():
    while True:
        try:
            log.info(f"Connecting to IRC: {IRC_SERVER}:{IRC_PORT}")
            params = ConnectionParams(
                nickname=IRC_NICK,
                host=IRC_SERVER,
                port=IRC_PORT,
                tls=True
            )
            await irc_bot.add_server("auth", params)
            
            # Wait for connection and join channels
            await asyncio.sleep(2)
            server = irc_bot.servers.get("auth")
            if server and IRC_CHANNELS:
                await server.send(build("JOIN", [IRC_CHANNELS]))
            
            log.info("IRC connected")
            break
        except Exception as e:
            log.error(f"IRC connection error: {e}")
            await asyncio.sleep(5)


@app.on_event("startup")
async def startup():
    global redis_client
    redis_client = redis.from_url(REDIS_URL)
    asyncio.create_task(connect_irc())


@app.get("/auth")
async def auth(request: Request):
    log.debug("--- /auth endpoint triggered ---")
    log.debug(f"Headers: {dict(request.headers)}")
    log.debug(f"Cookies: {dict(request.cookies)}")

    original_url = request.headers.get("X-Original-URL")
    if not original_url:
        log.error("Missing X-Original-URL header")
        raise HTTPException(status_code=401, detail="oops... something went wrong with the request")

    original_domain = urlparse(original_url).netloc
    if not original_domain:
        log.error("Invalid X-Original-URL header, cannot parse netloc")
        raise HTTPException(status_code=401, detail="hmm... the url looks a bit wonky")

    canonical_domain = request.headers.get("X-Auth-Share-Domain", original_domain)
    log.debug(f"Determined canonical_domain: {canonical_domain}")

    allowed_channels_str = request.headers.get("X-Auth-Channels")
    if not allowed_channels_str:
        log.error("Missing X-Auth-Channels header")
        raise HTTPException(status_code=403, detail="hmm... no channels were specified")

    session = await get_session_from_cookie(request, canonical_domain)

    if session:
        nick = session.get(b'nick', b'').decode()
        log.debug(f"Session found for nick: {nick}")
        is_authorized = False
        
        server = irc_bot.servers.get("auth")
        if server:
            for channel_name in allowed_channels_str.split(','):
                log.debug(f"Checking membership for '{nick}' in channel '{channel_name}'")
                channel = server.channels.get(channel_name)
                if channel and nick.lower() in [u.lower() for u in channel.users]:
                    is_authorized = True
                    log.info(f"Authorization SUCCESS for '{nick}' via channel '{channel_name}'")
                    break

        if is_authorized:
            log.debug(f"--- /auth finished: 200 OK for user {nick} ---")
            return Response(status_code=200, headers={"X-Auth-User": nick})
        else:
            log.warning(f"Authorization FAILED for '{nick}'. Not in required channels: {allowed_channels_str}")
            log.debug("--- /auth finished: 403 Forbidden ---")
            raise HTTPException(status_code=403, detail="Forbidden: You are not in the required channels.")
    else:
        log.debug("No valid session found. Generating redirect token.")
        redirect_payload = {
            "share_domain": canonical_domain,
            "channels": allowed_channels_str,
            "redirect_url": original_url,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
            "verify_token": secrets.token_urlsafe(24)
        }
        redirect_token = jwt.encode(redirect_payload, JWT_SECRET_KEY, algorithm="HS256")

        log.debug("--- /auth finished: 401 Unauthorized with redirect token ---")
        return Response(status_code=401, headers={"X-Auth-Redirect-Token": redirect_token})


@app.get("/login")
async def login(request: Request):
    redirect_jwt = request.query_params.get("token")
    if not redirect_jwt:
        return simple_response("too broken 4 irc auth", "<h2>oops</h2><p>missing login token...</p>", 400)

    try:
        payload = jwt.decode(redirect_jwt, JWT_SECRET_KEY, algorithms=["HS256"])
        canonical_domain = payload["share_domain"]
        channels = payload["channels"]
        redirect_url = payload["redirect_url"]
        verify_token = payload["verify_token"]
    except jwt.ExpiredSignatureError:
        return simple_response("too late 4 irc auth", "<h2>whoops</h2><p>the link expired... try again?</p>", 400)
    except jwt.InvalidTokenError:
        return simple_response("hackers in my irc auth", "<h2>hmm</h2><p>something's off with this link...</p>", 400)

    challenge_key = f"challenge:{verify_token}"

    existing_challenge = await redis_client.hgetall(challenge_key)
    if not existing_challenge:
        await redis_client.hset(challenge_key, mapping={
            "canonical_domain": canonical_domain,
            "channels": channels,
            "redirect_url": redirect_url,
        })
        await redis_client.expire(challenge_key, 600)
        log.debug(f"Created new challenge for verify_token: {verify_token}")
    else:
        log.debug(f"Using existing challenge for verify_token: {verify_token}")

    result_key = f"result:{verify_token}"
    result = await redis_client.hgetall(result_key)
    if result:
        status = result.get(b'status', b'').decode()
        if status == 'success':
            return RedirectResponse(f"/login/success?token={verify_token}", status_code=302)
        elif status == 'error':
            message = result.get(b'message', b'authentication failed').decode()
            return simple_response("irc authentication...failed", f"<h2>authentication failed</h2><p class='status status-error'>{message}</p>")

    return simple_response("irc authentication!", f"""
        <h2>chi va là?</h2>
        <p><strong>you are being logged in to </strong> {urlparse(redirect_url).netloc}</p>
        <p>proof of work? very simple, message <strong>{IRC_NICK}</strong>:</p>
        <div class="accent-box">
            <span class="copy-command" onclick="copyCommand(this)">/msg {IRC_NICK} {verify_token}</span>
        </div>
        <div id="status" class="status">waiting for verification...</div>
        <div id="copy-feedback" class="status"></div>
        <script>
        let copyTimeout;
        function copyCommand(el) {{
            navigator.clipboard.writeText(el.innerText).then(() => {{
                const feedbackEl = document.getElementById('copy-feedback');
                feedbackEl.innerHTML = 'copied to clipboard hehe';
                feedbackEl.className = 'status status-success';

                clearTimeout(copyTimeout);
                copyTimeout = setTimeout(() => {{
                    feedbackEl.innerHTML = '';
                    feedbackEl.className = 'status';
                }}, 2000);
            }});
        }}

        const es = new EventSource('/sse/{verify_token}');
        const statusEl = document.getElementById('status');
        es.addEventListener('success', e => {{
            statusEl.innerHTML = 'authentication successful! redirecting...';
            statusEl.className = 'status status-success';
            setTimeout(() => window.location.href = '/login/success?token={verify_token}&jwt={quote(redirect_jwt)}', 1000);
        }});
        es.addEventListener('error', e => {{
            statusEl.innerHTML = e.data;
            statusEl.className = 'status status-error';
        }});
        window.onbeforeunload = () => es.close();
        </script>
    """)


@app.get("/login/success")
async def login_success(request: Request):
    """Handle successful authentication and set cookies."""
    verify_token = request.query_params.get("token")
    if not verify_token:
        return simple_response("something broke my irc auth", "<h2>oops</h2><p>missing token...</p>", 400)

    challenge_key = f"challenge:{verify_token}"
    challenge_data = await redis_client.hgetall(challenge_key)
    if not challenge_data:
        return simple_response("super broken irc auth", "<h2>can't find it</h2><p>session not found or expired...</p>", 404)

    result_key = f"result:{verify_token}"
    result = await redis_client.hgetall(result_key)
    if not result or result.get(b'status', b'').decode() != 'success':
        return simple_response("not ready yet! irc auth", "<h2>not ready yet</h2><p>authentication still in progress...</p>", 400)

    canonical_domain = challenge_data[b'canonical_domain'].decode()
    redirect_url = challenge_data[b'redirect_url'].decode()
    auth_token = result.get(b'auth_token', b'').decode()
    nick = result.get(b'nick', b'').decode()

    if not auth_token:
        return simple_response("oops - irc auth", "<h2>oops</h2><p>token went missing somehow...</p>", 500)

    cookie_name = f"irc_auth_{secrets.token_urlsafe(8)}"
    response = RedirectResponse(redirect_url, status_code=302)

    hax = [canonical_domain, '.'.join(request.url.hostname.split('.')[-2:]), request.url.hostname, urlparse(redirect_url).hostname]
    hax += [f".{d}" for d in hax if d and not d.startswith('.')]
    hax = list(set(hax))
    for domain in hax:
        response.set_cookie(
            key=cookie_name,
            value=auth_token,
            domain=domain,
            max_age=COOKIE_TTL,
            secure=True,
            httponly=True,
            samesite="lax"
        )

    log.info(f"authentication successful for {nick}... setting cookie '{cookie_name}' for domains '{hax}' and redirecting to '{redirect_url}'")

    await redis_client.delete(challenge_key)
    await redis_client.delete(result_key)

    return response


@app.get("/sse/{verify_token}")
async def sse_challenge_events(verify_token: str):
    if not await redis_client.exists(f"challenge:{verify_token}"):
        raise HTTPException(status_code=404, detail="challenge not found or expired...")

    async def event_stream():
        queue = asyncio.Queue()
        sse_queues[verify_token] = queue
        try:
            yield "event: open\ndata: connection established\n\n"
            while True:
                data = await queue.get()
                yield data
        except asyncio.CancelledError:
            pass
        finally:
            sse_queues.pop(verify_token, None)

    return StreamingResponse(event_stream(), media_type="text/event-stream")

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
