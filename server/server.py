from flask import Flask, request, jsonify
import requests
import csv
from datetime import datetime
import os

app = Flask(__name__)

# WAF URL
WAF_URL = 'http://rb_waf/'  # Adjust if necessary

# ML Service URL (Assuming it runs on port 8000 in the same network)
ML_URL = 'http://ml_waf:8000/'  # Adjust if necessary

# Ensure the logs directory exists
LOG_DIRECTORY = 'logs'
LOG_FILE_PATH = os.path.join(LOG_DIRECTORY, 'server_logs.csv')

if not os.path.exists(LOG_DIRECTORY):
    os.makedirs(LOG_DIRECTORY)
    print(f"Created log directory at {LOG_DIRECTORY}")

# Initialize the log file with headers if it doesn't exist
if not os.path.isfile(LOG_FILE_PATH):
    with open(LOG_FILE_PATH, mode='w', newline='') as file:
        writer = csv.writer(file)
        header = [
            'Timestamp',
            'Payload',
            'WAF_Prediction_Timestamp',
            'WAF_Prediction',
            'ML_Prediction_Timestamp',
            'ML_Prediction'
        ]
        writer.writerow(header)
    print(f"Initialized log file with headers at {LOG_FILE_PATH}")

# Function to send request to WAF
def send_request_to_waf(payload):
    try:
        url = WAF_URL
        params = {
            'exec': payload
        }
        response = requests.get(url, params=params)
        waf_timestamp = datetime.now().isoformat()
        return response.status_code, response.text, waf_timestamp
    except requests.exceptions.RequestException as e:
        waf_timestamp = datetime.now().isoformat()
        return 'Error', str(e), waf_timestamp

# Function to send request to ML Service
def send_request_to_ml(payload):
    try:
        url = ML_URL
        params = {
            'q': payload
        }
        response = requests.get(url, params=params)
        ml_timestamp = datetime.now().isoformat()
        if response.status_code == 200:
            return 200, 'Accepted', ml_timestamp
        else:
            return 403, 'Rejected', ml_timestamp
    except requests.exceptions.RequestException as e:
        ml_timestamp = datetime.now().isoformat()
        return 'Error', str(e), ml_timestamp

# Route to receive requests from client
@app.route('/request', methods=['POST'])
def handle_request():
    payload = request.json.get('payload', '').strip()
    overall_timestamp = datetime.now().isoformat()

    # Send request to WAF
    waf_status_code, waf_response_body, waf_timestamp = send_request_to_waf(payload)

    # Send request to ML Service
    ml_status_code, ml_prediction, ml_timestamp = send_request_to_ml(payload)

    # Log to server-side CSV file
    log_entry = [
        overall_timestamp,
        payload,
        waf_timestamp,
        waf_status_code,
        ml_timestamp,
        ml_prediction
    ]

    try:
        with open(LOG_FILE_PATH, mode='a', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(log_entry)
        print(f"Logged request for payload: {payload}")
    except Exception as e:
        print(f"Failed to save log entry: {e}")

    # Return response to client
    return jsonify({
        'payload': payload,
        'WAF_status_code': waf_status_code,
        'ML_status_code': ml_status_code
    })

if __name__ == '__main__':
    # Ensure the server is accessible from other containers by setting host to '0.0.0.0'
    app.run(host='0.0.0.0', port=5000)
