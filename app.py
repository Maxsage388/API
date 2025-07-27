from flask import Flask, request, jsonify
import re

app = Flask(__name__)

# Simple regex pattern to check if URL is valid
URL_REGEX = re.compile(r"^(http|https)://")

@app.route('/check', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get("url", "")
    
    if URL_REGEX.match(url):
        return jsonify({"status": "Safe"})
    else:
        return jsonify({"status": "Not Safe"})

@app.route('/', methods=['GET'])
def index():
    return "Link Safety API is running!"
