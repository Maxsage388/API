import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')

@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    url = data.get('url')

    if not url:
        return jsonify({'error': 'URL is required'}), 400

    headers = {
        "x-apikey": API_KEY
    }
    scan_url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(scan_url, headers=headers, data={"url": url})
    
    if response.status_code == 200:
        scan_id = response.json()['data']['id']
        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        result = requests.get(report_url, headers=headers)
        return jsonify(result.json())
    else:
        return jsonify({'error': 'Scan failed', 'details': response.text}), 500

@app.route('/')
def home():
    return 'VirusTotal URL Scanner API is running.'
