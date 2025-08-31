# ----------------------------------
# Honeypot CAPTCHA program
# The purpose of this application is a proof-of-concept spite machine to create a log of users on a validation website
# This is not intended for public use, it's purely for educational/demo purposes
# Intended to be deployed on an AWS EC2 instance that can be connected to CloudWatch
# ----------------------------------

import json
import os
from datetime import datetime, timezone
from uuid import uuid4
import string
import random
import logging

from flask import Flask, render_template_string, request, redirect, url_for, session
from werkzeug.middleware.proxy_fix import ProxyFix

# Optional hardening and rate limiting
try:
	from flask_limiter import Limiter
	from flask_limiter.util import get_remote_address
except Exception:
	Limiter = None

try:
	from flask_talisman import Talisman
except Exception:
	Talisman = None

try:
	import boto3
	from botocore.exceptions import ClientError
except Exception:
	boto3 = None

# ----------------------------------
# Config
# ----------------------------------

LOG_PATH = os.environ.get("HP_LOG_PATH", "/var/log/honeypot/honeypot.ndjson")

AWS_LOGS_ENABLE = os.environ.get("HP_AWS_LOGS_ENABLE", "false").lower() == "true"
AWS_REGION = os.environ.get("AWS_REGION", "us-west-1")
AWS_LOG_GROUP = os.environ.get("HP_AWS_LOG_GROUP", "honeypot-captcha")
AWS_LOG_STREAM = os.environ.get("HP_AWS_LOG_STREAM", "requests")

# ----------------------------------
# App factory
# ----------------------------------
def create_app() -> Flask:
	app = Flask(__name__)

	# Secret key generation -- ain't no way I'm hardcoding this in lmao
	app.secret_key = os.environ.get("FLASK_SECRET_KEY", os.urandom(32))

	# Trusting a single proxy (nginx) for X-Forwarded-For/Pronto
	app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

	# Securing session cookies
	app.config.update(
		SESSION_COOKIE_HTTPONLY=True,
		SESSION_COOKIE_SECURE=True,		# Require HTTPS in prod
		SESSION_COOKIE_SAMESITE="Lax",
		PREFERRED_URL_SCHEME="https",
	)

	# Security headers (CSP, etc.)
	# For this program, we will allow inline styles to keep template simple
	# For stricter CSP, I'd want to move styles to a static CSS file and drop 'unsafe-inline'
	# But yes, this technically should resolve a lower security grade when checking for CSP headers on something like SSL Labs

	if Talisman:
		csp = {
			'default-src': ["'self'"],
			'style-src': ["'self'", "'unsafe-inline'"],
		}
		Talisman(app, content_security_policy=csp, force_https=True)
	
	# Rate limiting the site to reduce bot abuse...
	# ...Ironically, the whole original purpose of the site is supposed to be a CAPTCHA to avoid this, but without using Google's reCAPTCHA or other advance CAPTCHA service, it kinda defeats the purpose?
	# Like, surely a more advanced bot or AI algo can solve this captcha pretty easily
	# It's not even security through obscurity at this point, but like security theater ¯\_(ツ)_/¯
	# Idk, tl;dr: don't rely on this app as a full on CAPTCHA service for your applications, it's only a demo LOL
	# But anyways, the rate limit is set to 60 requests per minute, it technically can be adjusted in line [SOMETHING FOR LATER LOL]
	# But I set it to this because surely no human is solving a CAPTCHA a second right

	if Limiter:
		limiter = Limiter(get_remote_address, app=app,
							default_limits=["60 per minute"],
							storage_uri=os.environ.get("HP_LIMITER_STORAGE", "memory://"))
	else:
		limiter = None

	# Ensuring log directory exists with secure permissions
	log_dir = os.path.dirname(LOG_PATH) or "."
	os.makedirs(log_dir, mode=0o700, exist_ok=True)

	# Touch the file with secure perms if missing
	if not os.path.exists(LOG_PATH):
		with open(LOG_PATH, "a", encoding="utf-8") as _:
			pass
		os.chmod(LOG_PATH, 0o600)

	# CAPTCHA helpers -- Generates a CAPTCHA of 6 characters with a mix of ascii uppercase and digits
	def generate_captcha(length: int=6) -> str:
		return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

	# CloudWatch state
	cw_client = None
	cw_next_token = None
	
	def get_cw_client():
	    """Initialize CloudWatch client and ensure log group/stream exist."""
	    global cw_client, cw_next_token
	
	    if not AWS_LOGS_ENABLE or boto3 is None:
	        return None
	
	    if cw_client is None:
	        cw_client = boto3.client("logs", region_name=AWS_REGION)

	        # Ensure log group exists
	        try:
	            cw_client.create_log_group(logGroupName=AWS_LOG_GROUP)
	        except ClientError as e:
	            if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
	                logging.error(f"CloudWatch log group error: {e}")
	                return None

	        # Ensure log stream exists
	        try:
	            cw_client.create_log_stream(logGroupName=AWS_LOG_GROUP, logStreamName=AWS_LOG_STREAM)
	        except ClientError as e:
	            if e.response["Error"]["Code"] != "ResourceAlreadyExistsException":
	                logging.error(f"CloudWatch log stream error: {e}")
	                return None
	
	        # Fetch current sequence token
	        try:
	            resp = cw_client.describe_log_streams(
	                logGroupName=AWS_LOG_GROUP,
	                logStreamNamePrefix=AWS_LOG_STREAM,
	                limit=1
	            )
	            streams = resp.get("logStreams", [])
	            if streams:
	                cw_next_token = streams[0].get("uploadSequenceToken")
	        except Exception as e:
	            logging.warning(f"Could not get sequence token: {e}")
	
	    return cw_client
	
	def send_to_cloudwatch(entry: dict):
	    """Send a single log entry to CloudWatch, auto-handling sequence token errors."""
	    global cw_next_token
	
	    if not AWS_LOGS_ENABLE or boto3 is None:
	        return
	
	    client = get_cw_client()
	    if client is None:
	        return
	
	    event = {
	        "timestamp": int(datetime.now(tz=timezone.utc).timestamp() * 1000),
	        "message": json.dumps(entry, separators=(",", ":"))
	    }

	    kwargs = {
	        "logGroupName": AWS_LOG_GROUP,
	        "logStreamName": AWS_LOG_STREAM,
	        "logEvents": [event]
	    }

	    if cw_next_token:
	        kwargs["sequenceToken"] = cw_next_token
	
	    try:
	        resp = client.put_log_events(**kwargs)
	        cw_next_token = resp.get("nextSequenceToken")
	    except ClientError as e:
	        code = e.response.get("Error", {}).get("Code")
	        if code in ("InvalidSequenceTokenException", "DataAlreadyAcceptedException"):
	            # Refresh token and retry once
	            try:
	                resp = client.describe_log_streams(
	                    logGroupName=AWS_LOG_GROUP,
	                    logStreamNamePrefix=AWS_LOG_STREAM,
	                    limit=1
	                )
	                streams = resp.get("logStreams", [])
	                if streams:
	                    cw_next_token = streams[0].get("uploadSequenceToken")
	                    kwargs["sequenceToken"] = cw_next_token
	                    resp = client.put_log_events(**kwargs)
	                    cw_next_token = resp.get("nextSequenceToken")
	            except Exception as e2:
	                logging.error(f"CloudWatch retry failed: {e2}")
	        else:
	            logging.error(f"CloudWatch put_log_events error: {e}")
	    except Exception as e:
	        logging.error(f"CloudWatch unknown error: {e}")


	# Append one-line JSON to NDJSON file (atomic-ish append)
	def append_ndjson(entry: dict):
		line = json.dumps(entry, separators=(",", ":")) + "\n"
		with open(LOG_PATH, "a", encoding="utf-8") as f:
			f.write(line)

	# Construct and persist an entry
	# NOTE: entry_number here is per-process and resets on EC2 restart
	# I could technically use a small DB or derive from CloudWatch for a persistent counter
	# But frankly that's too much work for a small scale op lmao

	app._entry_counter = 0

	def log_request_secure(req):
	    """Log a request locally and optionally to CloudWatch."""
	    app._entry_counter += 1
	    entry = {
	        "entry_number": app._entry_counter,
	        "timestamp": datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z"),
	        "user-agent": req.headers.get("User-Agent", ""),
	        "ip": req.remote_addr or "",
	        "id": uuid4().hex
	    }
	
	    # Write to local NDJSON file
	    append_ndjson({k: entry[k] for k in ("entry_number", "timestamp", "user-agent", "ip")})
	
	    # Send to CloudWatch asynchronously
	    try:
	        send_to_cloudwatch({k: entry[k] for k in ("entry_number", "timestamp", "user-agent", "ip")})
	    except Exception as e:
	        logging.warning(f"Failed to send to CloudWatch: {e}")
	
	    return entry

# ----------------------------------
# Routes
# ----------------------------------

	INDEX_HTML = """
	<html>
		<body style="text-align:center; margin-top:100px;">
			<form action="{{ url_for('captcha') }}" method="get">
				<button style="background-color:green; color:white; padding:20px; font-size:24px; border:none; border-radius:10px;">
					Validate
				</button>
			</form>
		</body>
	</html>
	"""

	CAPTCHA_HTML = """
	<html>
		<body style="text-align:center; margin-top:100px;">
			{% if error %}
				<p style="color:red;">Incorrect. Try again.</p>
			{% endif%}
			<form method="post">
				<p>Enter the text: <b>{{ captcha }}</b></p>
				<input type="text" name="captcha_input" autocomplete="off" required>
				<button type="submit">Submit</button>
			</form>
		</body>
	</html>
	"""

	SUCCESS_HTML = """
	<html>
		<body style="text-align:center; margin-top:100px; color:green;">
			<h1>Confirmed!</h1>
		</body>
	</html>
	"""

	@app.get("/")
	def index():
	    return render_template_string(INDEX_HTML)
	
	
	def register_captcha_route(app, limiter_enabled=False, limiter=None):
	    route_decorator = limiter.limit("10 per minute") if limiter_enabled and limiter else lambda f: f
	
	    @app.route("/captcha", methods=["GET", "POST"])
	    @route_decorator
	    def captcha():
	        if request.method == "POST":
	            answer = (request.form.get("captcha_input", "").strip()).upper()
	            expected = session.get("captcha_text", "")
	            if answer == expected:
	                log_request_secure(request)
	                return redirect(url_for("success"))
	            # Wrong answer → generate new captcha and show error
	            new_captcha = generate_captcha()
	            session["captcha_text"] = new_captcha
	            return render_template_string(CAPTCHA_HTML, captcha=new_captcha, error=True)
	
	        # GET request → generate new captcha
	        captcha_text = generate_captcha()
	        session["captcha_text"] = captcha_text
	        return render_template_string(CAPTCHA_HTML, captcha=captcha_text, error=False)
	
	
	# Call the function to register the route
	register_captcha_route(app, limiter_enabled=bool(limiter), limiter=limiter)

	@app.get("/success")
	def success():
		return render_template_string(SUCCESS_HTML)

	return app

app = create_app()

if __name__ == "__main__":

	# Bind to all interfaces; debug disabled for prod safety
	app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
