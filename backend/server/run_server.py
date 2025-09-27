from flask import Flask, request, jsonify
import base64
import os
from flasgger import Swagger, swag_from

app = Flask(__name__)
swagger = Swagger(app)

KM_API_TOKEN = os.environ.get("KM_API_TOKEN", "demo-token")
VALID_KEY_LENGTHS = {16, 24, 32}  # Acceptable AES key sizes in bytes

@app.route('/api/keys', methods=['POST'])
@swag_from({
    'tags': ['Quantum Key API'],
    'parameters': [
        {
            'name': 'Authorization',
            'in': 'header',
            'type': 'string',
            'required': True,
            'description': 'Bearer token for authentication, e.g. "Bearer demo-token"'
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'user': {
                        'type': 'string',
                        'example': 'user@example.com'
                    },
                    'key_length': {
                        'type': 'integer',
                        'enum': [16, 24, 32],
                        'default': 32
                    }
                },
                'required': ['user']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Quantum key generated successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'user': {'type': 'string'},
                    'quantum_key': {'type': 'string'},
                    'length': {'type': 'integer'}
                }
            }
        },
        400: {
            'description': 'Bad Request'
        },
        401: {
            'description': 'Unauthorized'
        }
    }
})
def get_key():
    auth = request.headers.get('Authorization')
    if auth != f'Bearer {KM_API_TOKEN}':
        return jsonify({"error": "Unauthorized"}), 401

    if not request.is_json:
        return jsonify({"error": "Invalid or missing JSON body"}), 400

    data = request.get_json()
    user = data.get('user')
    key_length = data.get('key_length', 32)

    if not user:
        return jsonify({"error": "Missing 'user' field"}), 400

    try:
        key_length = int(key_length)
    except (TypeError, ValueError):
        return jsonify({"error": "'key_length' must be an integer"}), 400

    if key_length not in VALID_KEY_LENGTHS:
        return jsonify({"error": f"'key_length' must be one of {sorted(VALID_KEY_LENGTHS)} bytes"}), 400

    quantum_key = os.urandom(key_length)
    key_b64 = base64.b64encode(quantum_key).decode('ascii')

    return jsonify({
        "user": user,
        "quantum_key": key_b64,
        "length": key_length
    })

if __name__ == '__main__':
    app.run(port=5000)