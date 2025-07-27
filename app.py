from flask import Flask, request, jsonify
import requests
import os

app = Flask(__name__)
API_KEY = os.getenv("GOOGLE_API_KEY")

@app.route('/check', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    safe_browsing_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + API_KEY
    body = {
        "client": {"clientId": "url-checker", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    res = requests.post(safe_browsing_url, json=body)
    if res.status_code != 200:
        return jsonify({"error": "API request failed"}), 500

    if res.json().get("matches"):
        return jsonify({"safe": False, "message": "⚠️ Not Safe"})
    else:
        return jsonify({"safe": True, "message": "✅ Safe"})

if __name__ == '__main__':
    app.run()
