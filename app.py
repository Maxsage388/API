from flask import Flask, request, jsonify
import os
import re

app = Flask(__name__)

# Load API key from environment
API_KEY = os.getenv("API_KEY")

# Very basic unsafe URL patterns (just an offline example)
UNSAFE_KEYWORDS = ['phishing', 'malware', 'scam', 'fake', 'dodgy']

def is_url_safe(url):
    for word in UNSAFE_KEYWORDS:
        if word in url.lower():
            return False
    # Basic regex check
    regex = re.compile(
        r'^(http|https):\/\/[^\s\/$.?#].[^\s]*$'
    )
    return re.match(regex, url) is not None

@app.route('/check', methods=['POST'])
def check_link():
    data = request.json
    user_key = request.headers.get('Authorization')

    if user_key != API_KEY:
        return jsonify({'error': 'Invalid or missing API key'}), 401

    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    safe = is_url_safe(url)
    return jsonify({
        'url': url,
        'safe': safe,
        'message': "Safe ✅" if safe else "Not Safe ❌"
    })

@app.route('/')
def home():
    return jsonify({"message": "Link Safety API is running."})

if __name__ == '__main__':
    app.run(debug=True)
