# utils.py

import os
import requests
from flask import jsonify

def call_service(method, url, headers=None, json=None, params=None):
    try:
        response = requests.request(method, url, headers=headers, json=json, params=params)
        return jsonify(response.json()), response.status_code, response.headers.items()
    except requests.exceptions.RequestException as e:
        return jsonify({'message': str(e)}), 500

def get_doc_path(filename):
    return os.path.join(os.path.dirname(__file__), 'docs', filename)
