import pylibmc
import uuid
from cachelib import SimpleCache
from flask_session import Session
from flask import Flask, session, request

app = Flask(__name__)
app.secret_key = uuid.uuid4()
MEMCACHED_URL = ["memcached:11211"]

if MEMCACHED_URL:
    app.config["SESSION_TYPE"] = "memcached"
    app.config["SESSION_MEMCACHED"] = pylibmc.Client(MEMCACHED_URL)
    app.config["SESSION_PERMANENT"] = True
    app.config["SESSION_USE_SIGNER"] = False
    app.config["SESSION_KEY_PREFIX"] = "BT_:"
    app.config["SESSION_COOKIE_NAME"] = "notsecret"
    app.config["PERMANENT_SESSION_LIFETIME"] = 86400 * 30
    app.config.from_object(__name__)
    Session(app)

@app.route("/set/")
def set():
    value = str(request.args.get('key'))
    if value:
        session["key"] = value
        return "Success!"
    else:
        return "Error: key is None!"


@app.route("/get/")
def get():
    return session.get("key", "not set")


@app.route("/")
def main():
    message = """
    <html>
    <body>
    <p>
    Hello User 👋,
    <br>
    This application uses Memcached to store user key/value
    Use <a href="/set/?key=value">set value</a>
    And  <a href="/get/">get value</a>
    </p>
    </body>
    </html>
    """
    return message


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)