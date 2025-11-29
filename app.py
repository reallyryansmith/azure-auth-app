import base64
import json
from flask import Flask, request

app = Flask(__name__)


def get_current_user():
    """
    Reads X-MS-CLIENT-PRINCIPAL from headers (injected by App Service Authentication),
    base64-decodes it, and returns a small user dict.
    """
    header = request.headers.get("X-MS-CLIENT-PRINCIPAL")
    if not header:
        return None

    decoded = base64.b64decode(header)
    data = json.loads(decoded.decode("utf-8"))

    claims = {c["typ"]: c["val"] for c in data.get("claims", [])}

    return {
        "name": claims.get(
            "name",
            claims.get(
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
            ),
        ),
        "oid": claims.get("http://schemas.microsoft.com/identity/claims/objectidentifier"),
        "preferred_username": claims.get("preferred_username"),
    }


@app.route("/")
def index():
    user = get_current_user()
    if not user:
        # If Easy Auth isn't configured, you'll see this locally or anonymously.
        return "Hello, anonymous user. If this is running in Azure with auth, you should be redirected to sign in."

    return (
        f"<h1>Hello, {user['name']}</h1>"
        f"<p>Username: {user['preferred_username']}</p>"
        f"<p>Object ID: {user['oid']}</p>"
    )


if __name__ == "__main__":
    # For local testing only
    app.run(host="0.0.0.0", port=8000, debug=True)
