from flask import Flask, request, jsonify
import os
import requests

app = Flask(__name__)
API_KEY = os.getenv("API_KEY")
GOOGLE_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")

def is_url_safe(url):
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_KEY}"
    payload = {
        "client": {
            "clientId": "render-api",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    res = requests.post(endpoint, json=payload)
    if res.status_code != 200:
        return None
    return res.json() == {}

@app.route("/check", methods=["POST"])
def check():
    user_key = request.headers.get("Authorization")
    if user_key != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    url = data.get("url")
    if not url:
        return jsonify({"error": "URL required"}), 400

    safe = is_url_safe(url)
    if safe is None:
        return jsonify({"error": "API error"}), 500

    return jsonify({
        "url": url,
        "safe": safe,
        "message": "✅ Safe" if safe else "❌ Not Safe"
    })

@app.route("/")
def home():
    return jsonify({"message": "URL Safety API Running."})
