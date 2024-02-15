from flask import make_response, jsonify

def create_response(message, status_code):
    return make_response(jsonify(message), status_code)