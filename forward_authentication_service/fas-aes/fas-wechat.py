#!/usr/bin/env python3
"""WeChat + phone binding FAS for openNDS fas_secure_enabled=3.

Environment variables:
  FASKEY, FLASK_SECRET_KEY, WECHAT_APPID, WECHAT_SECRET,
  PUBLIC_DOMAIN (for example https://fas.example.com), BASE_PATH (default /),
  USER_DB (default ./data/users.json), QUEUE_DIR (default ./queue),
  TOKEN_DIR (default ./tokens), USED_CODES_DIR (default ./used_codes),
  SMS_CODES_DIR (default ./sms_codes), MAC_FILE (optional), PORT (default 8080).

Run behind HTTPS with a production WSGI server, e.g. gunicorn. Do not expose
Flask's development server to the Internet.
"""

import base64
import binascii
import fcntl
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, abort, jsonify, make_response, redirect, request, session
from markupsafe import escape

BASE_DIR = Path(__file__).resolve().parent
FASKEY = os.environ.get("FASKEY", "")
if not FASKEY:
    raise RuntimeError("FASKEY environment variable is required and must match openNDS faskey")
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "")
if not FLASK_SECRET_KEY:
    raise RuntimeError("FLASK_SECRET_KEY environment variable is required")

WECHAT_APPID = os.environ.get("WECHAT_APPID", "")
WECHAT_SECRET = os.environ.get("WECHAT_SECRET", "")
PUBLIC_DOMAIN = os.environ.get("PUBLIC_DOMAIN", "").rstrip("/")
BASE_PATH = os.environ.get("BASE_PATH", "/").strip() or "/"
if not BASE_PATH.startswith("/"):
    BASE_PATH = "/" + BASE_PATH
BASE_PATH = BASE_PATH.rstrip("/")

USER_DB = Path(os.environ.get("USER_DB", str(BASE_DIR / "data" / "users.json")))
QUEUE_DIR = Path(os.environ.get("QUEUE_DIR", str(BASE_DIR / "queue")))
TOKEN_DIR = Path(os.environ.get("TOKEN_DIR", str(BASE_DIR / "tokens")))
USED_CODES_DIR = Path(os.environ.get("USED_CODES_DIR", str(BASE_DIR / "used_codes")))
SMS_CODES_DIR = Path(os.environ.get("SMS_CODES_DIR", str(BASE_DIR / "sms_codes")))
MAC_FILE = os.environ.get("MAC_FILE", "")

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1").lower() not in ("0", "false", "no"),
    MAX_CONTENT_LENGTH=64 * 1024,
)
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
logger = logging.getLogger("fas-wechat")

MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$", re.I)
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
TOKEN_RE = re.compile(r"^[a-f0-9]{8}$", re.I)
PHONE_RE = re.compile(r"^1[3-9]\d{9}$")


@contextmanager
def exclusive_lock(path: Path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def load_users() -> dict:
    if not USER_DB.is_file():
        return {}
    try:
        value = json.loads(USER_DB.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        logger.exception("Cannot read user database")
        return {}


def bind_user(openid: str, phone: str) -> None:
    lock_path = USER_DB.with_name(USER_DB.name + ".lock")
    with exclusive_lock(lock_path):
        users = load_users()
        users[openid] = {
            "phone": phone,
            "nickname": "微信用户",
            "bind_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        }
        encoded = json.dumps(users, ensure_ascii=False, indent=2).encode("utf-8")
        atomic_write(USER_DB, encoded)


def get_user(openid: str):
    with exclusive_lock(USER_DB.with_name(USER_DB.name + ".lock")):
        return load_users().get(openid)


def auth_queue(gatewayhash: str, hid: str) -> str:
    if not HASH_RE.fullmatch(gatewayhash) or not hid or not FASKEY:
        raise ValueError("Invalid openNDS authentication parameters")
    rhid = hashlib.sha256((hid.strip() + FASKEY.strip()).encode("utf-8")).hexdigest()
    gateway_dir = QUEUE_DIR / gatewayhash
    gateway_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    # openNDS authmon format: rhid sessionlength uploadrate downloadrate uploadquota downloadquota custom
    line = f"{rhid} 0 0 0 0 0 {base64.b64encode(b'').decode('ascii')} \n".encode("ascii")
    lock = gateway_dir / ".queue.lock"
    with exclusive_lock(lock):
        atomic_write(gateway_dir / rhid, line)
    if MAC_FILE:
        try:
            mac = str(session.get("clientmac", "")).lower()
            if MAC_RE.fullmatch(mac):
                path = Path(MAC_FILE)
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with exclusive_lock(path.with_name(path.name + ".lock")):
                    current = path.read_text(encoding="utf-8") if path.exists() else ""
                    if mac not in {line.strip().lower() for line in current.splitlines()}:
                        with path.open("a", encoding="utf-8") as stream:
                            stream.write(mac + "\n")
        except OSError:
            logger.exception("Could not append client MAC to MAC_FILE")
    return rhid


def authmon_response():
    """Handle authenticated requests from openNDS Authmon; return None if not one."""
    if "auth_get" not in request.form:
        return None

    action = request.form.get("auth_get", "")
    gatewayhash = request.form.get("gatewayhash", "")
    payload = request.form.get("payload", "")
    authmac = request.form.get("authmac", "")
    if not HASH_RE.fullmatch(gatewayhash) or action not in {"clear", "view", "list", "deauthed", "custom"}:
        abort(400)

    # The helper signs the exact base64 payload string sent in the form.
    signed = f"{action}\n{gatewayhash}\n{payload}".encode("utf-8")
    expected = hmac.new(FASKEY.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    if not re.fullmatch(r"[0-9a-f]{64}", authmac) or not hmac.compare_digest(expected, authmac):
        logger.warning("Authmon HMAC rejected: action=%s gatewayhash=%s authmac_present=%s", action, gatewayhash, bool(authmac))
        abort(403)

    gw_dir = QUEUE_DIR / gatewayhash
    if action == "clear":
        with exclusive_lock(gw_dir / ".queue.lock"):
            if gw_dir.is_dir():
                for path in gw_dir.iterdir():
                    if HASH_RE.fullmatch(path.name) and path.is_file():
                        path.unlink(missing_ok=True)
        return make_response("", 200)

    if action in {"deauthed", "custom"}:
        return make_response("ack", 200)

    try:
        decoded = base64.b64decode(payload, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        abort(400)

    with exclusive_lock(gw_dir / ".queue.lock"):
        if action == "view" and decoded != "none":
            # Authmon acknowledges using "* <rhid> ...".
            for rhid in decoded.split():
                if HASH_RE.fullmatch(rhid):
                    (gw_dir / rhid).unlink(missing_ok=True)
            return make_response("ack", 200)

        entries = []
        if gw_dir.is_dir():
            for path in sorted(gw_dir.iterdir()):
                if not HASH_RE.fullmatch(path.name) or not path.is_file():
                    continue
                try:
                    first_line = path.read_text(encoding="utf-8").splitlines()[0].strip()
                except (OSError, IndexError, UnicodeDecodeError):
                    continue
                if first_line:
                    entries.append(urllib.parse.quote(first_line, safe=""))
                if action == "list":
                    path.unlink(missing_ok=True)
        return make_response("*" + (" " + " ".join(entries) if entries else ""), 200)


def decrypt_fas(fas: str, iv_text: str):
    """Decrypt openNDS AES-256-CBC query using PHP/OpenSSL-compatible key padding."""
    try:
        ciphertext = base64.b64decode(fas, validate=True)
    except (binascii.Error, ValueError):
        return None
    iv = iv_text.encode("utf-8")
    if len(iv) != 16 or len(ciphertext) == 0 or len(ciphertext) % 16:
        return None
    # PHP openssl_decrypt pads/truncates a passphrase to the cipher key length.
    key = FASKEY.encode("utf-8")[:32].ljust(32, b"\0")
    try:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()
        params = {}
        for pair in plaintext.decode("utf-8").split(", "):
            if "=" in pair:
                name, value = pair.split("=", 1)
                params[name.strip()] = value.strip()
        return params
    except (ValueError, UnicodeDecodeError):
        return None


def request_client_params():
    params = {}
    clientmac = ""
    gatewayhash = ""
    if request.args.get("token"):
        token = request.args.get("token", "")
        if not TOKEN_RE.fullmatch(token):
            abort(400, "无效的认证链接，请重新扫码。")
        token_file = TOKEN_DIR / (token + ".json")
        if token_file.is_file():
            try:
                data = json.loads(token_file.read_text(encoding="utf-8"))
                clientmac = str(data.get("mac", ""))
                params["hid"] = str(data.get("hid", ""))
                params["clientip"] = str(data.get("ip", ""))
                gatewayhash = str(data.get("gw_hash", ""))
            except (OSError, json.JSONDecodeError):
                pass
    elif request.args.get("_test") == "1" or request.args.get("mac"):
        clientmac = request.args.get("mac", "08:00:27:11:d6:8f")
        params["hid"] = request.args.get("hid", "") or "test_hid_" + str(int(time.time()))
        params["clientip"] = request.args.get("ip", "192.168.56.101")
        gatewayhash = request.args.get("gw_hash", "ac8c4c8b3dde1cb59f314c559132130941d8f0147486d13ab2d252c8d9673011")
    else:
        fas = request.args.get("fas", "")
        iv = request.args.get("iv", "")
        if fas and iv:
            params = decrypt_fas(fas, iv) or {}
            clientmac = str(params.get("clientmac", ""))
            gatewayname = str(params.get("gatewayname", ""))
            gatewayhash = hashlib.sha256(gatewayname.strip().encode("utf-8")).hexdigest()
    return params, clientmac, gatewayhash


def json_response_error(message: str, status: int):
    return jsonify(status="error", msg=message), status


def sms_file(phone: str) -> Path:
    return SMS_CODES_DIR / (hashlib.md5(phone.encode("ascii")).hexdigest() + ".txt")


def oauth_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "openNDS-WeChat-FAS"})
    with urllib.request.urlopen(req, timeout=8) as response:
        return json.loads(response.read().decode("utf-8"))


def render_bind_form(openid: str, nickname: str, clientmac: str, hid: str, gatewayhash: str):
    # Hidden values retain the existing form contract with the PHP implementation.
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no'><title>绑定手机号</title>
<style>body{{font-family:-apple-system,sans-serif;padding:20px;background:#f4f4f9}}.card{{background:white;padding:20px;border-radius:12px;box-shadow:0 4px 12px #0001;max-width:400px;margin:40px auto;text-align:center}}.btn{{display:block;padding:12px;background:#07c160;color:white;border:0;border-radius:8px;font-weight:bold;margin-top:20px;width:100%;font-size:16px}}.input-group{{display:flex;gap:10px;margin:15px 0}}input[type=text]{{min-width:0;flex:1;box-sizing:border-box;padding:12px;border:1px solid #ddd;border-radius:8px;font-size:16px;text-align:center}}.btn-sms{{width:120px;background:#07c160;color:white;border:0;border-radius:8px}}.btn-sms:disabled{{background:#ccc}}</style></head><body>
<div class=card><h2>欢迎您，{escape(nickname)}</h2><p style='color:#666;font-size:14px'>请验证手机号完成上网</p>
<form method=post><input type=hidden name=action value=bind_phone><input type=hidden name=openid value='{escape(openid)}'><input type=hidden name=mac value='{escape(clientmac)}'><input type=hidden name=hid value='{escape(hid)}'><input type=hidden name=gw_hash value='{escape(gatewayhash)}'>
<input type=text name=phone id=phoneInput placeholder='请输入 11 位手机号' maxlength=11 required style='width:100%;margin:15px 0'><div class=input-group><input type=text name=sms_code placeholder='输入验证码' maxlength=6 required><button type=button class=btn-sms id=sendSmsBtn>获取验证码</button></div><button type=submit class=btn>验证并上网</button></form></div>
<script>document.getElementById('sendSmsBtn').onclick=function(){{const phone=document.getElementById('phoneInput').value,btn=this;if(!/^1[3-9]\\d{{9}}$/.test(phone)){{alert('请输入正确的手机号格式');return}}btn.disabled=true;btn.textContent='发送中...';fetch(location.pathname,{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},body:new URLSearchParams({{action:'send_sms',phone}})}}).then(r=>r.json()).then(d=>{{if(d.status!=='success')throw new Error(d.msg);alert(d.msg);let n=60;const timer=setInterval(()=>{{btn.textContent=n+' 秒后重发';if(--n<0){{clearInterval(timer);btn.disabled=false;btn.textContent='获取验证码'}},1000)}}).catch(e=>{{alert(e.message||'网络错误');btn.disabled=false;btn.textContent='获取验证码'}})}};</script></body></html>"""


def success_page():
    session.clear()
    return """<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>认证成功</title><style>body{font-family:-apple-system,sans-serif;padding:20px;background:#f4f4f9;text-align:center}.card{background:white;padding:40px 20px;border-radius:12px;box-shadow:0 4px 12px #0001;max-width:400px;margin:40px auto}h2{color:#07c160}p{color:#666;font-size:14px}</style></head><body><div class=card><h2>🎉 认证成功</h2><p>您的设备已成功连接网络！</p><p style='font-size:12px;color:#999;margin-top:20px'>页面将在 5 秒后跳转...</p></div><script>setTimeout(()=>location.href='https://www.baidu.com',5000)</script></body></html>"""


def create_oauth_token(clientmac: str, params: dict, gatewayhash: str) -> str:
    token = secrets.token_hex(4)
    TOKEN_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = {"mac": clientmac, "hid": params.get("hid", ""), "ip": params.get("clientip", ""), "gw_hash": gatewayhash}
    atomic_write(TOKEN_DIR / (token + ".json"), json.dumps(data).encode("utf-8"))
    return token


def handle_oauth_callback():
    state = urllib.parse.parse_qs(request.args.get("state", ""))
    token = (state.get("token") or [""])[0]
    if not TOKEN_RE.fullmatch(token):
        abort(400, "认证链接无效，请重新扫码。")
    token_file = TOKEN_DIR / (token + ".json")
    if not token_file.is_file():
        abort(400, "认证链接已失效，请重新扫码。")
    try:
        token_data = json.loads(token_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        abort(400, "认证链接已失效，请重新扫码。")

    code = request.args.get("code", "")
    if not code:
        abort(400, "微信授权码缺失，请重新扫码。")
    USED_CODES_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    used_path = USED_CODES_DIR / hashlib.md5(code.encode("utf-8")).hexdigest()
    with exclusive_lock(used_path.with_name(used_path.name + ".lock")):
        if used_path.exists():
            abort(400, "该授权链接已失效，请重新扫描二维码。")
        oauth_url = "https://api.weixin.qq.com/sns/oauth2/access_token?" + urllib.parse.urlencode({
            "appid": WECHAT_APPID, "secret": WECHAT_SECRET, "code": code, "grant_type": "authorization_code"
        })
        try:
            oauth = oauth_json(oauth_url)
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError):
            logger.exception("WeChat OAuth token request failed")
            abort(502, "微信授权服务暂时不可用，请重试。")
        if "openid" not in oauth or "access_token" not in oauth:
            abort(502, "微信授权失败，请重新扫码。")
        atomic_write(used_path, time.strftime("%Y-%m-%d %H:%M:%S").encode("ascii"))

    openid = str(oauth["openid"])
    user_url = "https://api.weixin.qq.com/sns/userinfo?" + urllib.parse.urlencode({
        "access_token": oauth["access_token"], "openid": openid, "lang": "zh_CN"
    })
    try:
        user_info = oauth_json(user_url)
    except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError):
        logger.exception("WeChat userinfo request failed")
        user_info = {}
    nickname = str(user_info.get("nickname", "微信用户"))
    clientmac = str(token_data.get("mac", ""))
    hid = str(token_data.get("hid", ""))
    gatewayhash = str(token_data.get("gw_hash", ""))
    session.update(wx_openid=openid, wx_nickname=nickname, clientmac=clientmac, hid=hid, gw_hash=gatewayhash)
    if get_user(openid) and get_user(openid).get("phone"):
        auth_queue(gatewayhash, hid)
        return success_page()
    return render_bind_form(openid, nickname, clientmac, hid, gatewayhash)


@app.route("/", methods=["GET", "POST"])
def fas_root():
    if request.method == "POST":
        # Authmon has a signed form with auth_get; handle it before user-facing forms.
        authmon = authmon_response()
        if authmon is not None:
            return authmon
        action = request.form.get("action", "")
        if action == "send_sms":
            phone = request.form.get("phone", "")
            if not PHONE_RE.fullmatch(phone):
                return json_response_error("手机号格式错误", 400)
            SMS_CODES_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
            code = f"{secrets.randbelow(900000) + 100000:06d}"
            atomic_write(sms_file(phone), code.encode("ascii"))
            # Demo only; integrate an SMS provider and remove the code from this response in production.
            return jsonify(status="success", msg=f"【测试环境】验证码为: {code}")

        if action == "bind_phone":
            phone = request.form.get("phone", "")
            sms_code = request.form.get("sms_code", "")
            openid = request.form.get("openid", "")
            clientmac = request.form.get("mac", "")
            hid = request.form.get("hid", "")
            gatewayhash = request.form.get("gw_hash", "")
            if not PHONE_RE.fullmatch(phone) or not openid or not MAC_RE.fullmatch(clientmac) or not hid or not HASH_RE.fullmatch(gatewayhash):
                abort(400, "参数无效，请重新扫码。")
            sms_path = sms_file(phone)
            with exclusive_lock(sms_path.with_name(sms_path.name + ".lock")):
                try:
                    saved_code = sms_path.read_text(encoding="ascii").strip()
                except OSError:
                    saved_code = ""
                if not saved_code or not hmac.compare_digest(saved_code, sms_code):
                    abort(400, "手机号或验证码错误，请返回重试。")
                bind_user(openid, phone)
                auth_queue(gatewayhash, hid)
                sms_path.unlink(missing_ok=True)
            session.update(wx_openid=openid, wx_bound=True, clientmac=clientmac, hid=hid, gw_hash=gatewayhash)
            return redirect("?done=1", code=303)
        abort(400)

    if request.args.get("done") == "1":
        return success_page()

    params, clientmac, gatewayhash = request_client_params()
    is_test = request.args.get("_test") == "1"
    user_agent = request.headers.get("User-Agent", "")
    is_wechat = "MicroMessenger" in user_agent or "wechatdevtools" in user_agent

    # Process WeChat OAuth callback before any previously established browser session.
    if is_wechat and request.args.get("code") and not is_test:
        try:
            return handle_oauth_callback()
        except (ValueError, OSError) as exc:
            logger.exception("FAS OAuth callback handling failed")
            abort(500, "认证处理失败，请稍后重试。")

    if is_wechat and session.get("wx_openid") and not is_test:
        openid = str(session["wx_openid"])
        clientmac = str(session.get("clientmac", clientmac))
        hid = str(session.get("hid", params.get("hid", "")))
        gatewayhash = str(session.get("gw_hash", gatewayhash))
        user = get_user(openid)
        if user and user.get("phone"):
            try:
                auth_queue(gatewayhash, hid)
            except (ValueError, OSError):
                logger.exception("FAS authentication queue write failed")
                abort(500, "认证处理失败，请稍后重试。")
            return success_page()
        return render_bind_form(openid, session.get("wx_nickname", "微信用户"), clientmac, hid, gatewayhash)

    if not is_wechat:
        qr_mac = clientmac or "08:00:27:11:d6:8f"
        qr_hid = str(params.get("hid", "test_hid"))
        qr_ip = str(params.get("clientip", "192.168.56.101"))
        if not HASH_RE.fullmatch(gatewayhash):
            abort(400, "缺少有效的网关参数，请从 openNDS 门户重新打开。")
        qr_data = f"{PUBLIC_DOMAIN}{BASE_PATH}/?" + urllib.parse.urlencode({"mac": qr_mac, "hid": qr_hid, "ip": qr_ip, "gw_hash": gatewayhash})
        qr_url = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=" + urllib.parse.quote(qr_data, safe="")
        return f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>WiFi 认证中心</title></head><body style='font-family:sans-serif;padding:20px;background:#f4f4f9;text-align:center'><div style='background:white;padding:20px;border-radius:12px;max-width:400px;margin:40px auto'><h2>WiFi 认证</h2><p>请使用微信扫一扫</p><img src='{escape(qr_url)}' alt='微信扫码认证' width=200 height=200></div></body></html>"

    if is_wechat and not is_test:
        if not WECHAT_APPID or not WECHAT_SECRET or not PUBLIC_DOMAIN:
            abort(500, "微信授权配置不完整。")
        if not MAC_RE.fullmatch(clientmac) or not params.get("hid") or not HASH_RE.fullmatch(gatewayhash):
            abort(400, "缺少有效的认证参数，请重新扫描二维码。")
        token = create_oauth_token(clientmac, params, gatewayhash)
        redirect_uri = f"{PUBLIC_DOMAIN}{BASE_PATH}/"
        oauth_url = "https://open.weixin.qq.com/connect/oauth2/authorize?" + urllib.parse.urlencode({
            "appid": WECHAT_APPID, "redirect_uri": redirect_uri, "response_type": "code",
            "scope": "snsapi_userinfo", "state": "token=" + token,
        }) + "#wechat_redirect"
        return redirect(oauth_url)

    return "请使用微信扫一扫打开认证页面。", 400


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify(status="ok")


if __name__ == "__main__":
    # Development only. Use gunicorn/uwsgi behind a TLS reverse proxy in production.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), debug=False)
