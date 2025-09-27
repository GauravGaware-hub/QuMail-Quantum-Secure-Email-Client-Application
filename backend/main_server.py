from flask import Flask, request, jsonify, session
from flask_cors import CORS
import os
from app_core import QuMailApp
import base64

app = Flask(__name__)
CORS(app, supports_credentials=True)
app.secret_key = os.urandom(24)

qumail_app = QuMailApp()

def require_login():
    if 'user_email' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    return None

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if qumail_app.login(email, password):
            session['user_email'] = email
            return jsonify({'token': f'token_{email}', 'success': True})
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        qumail_app.register_user(
            email, password, 'demo-token',
            'smtp.gmail.com', 587, 'imap.gmail.com', 993
        )
        return jsonify({'success': True}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/send', methods=['POST'])
def send_email():
    try:
        err = require_login()
        if err:
            return err

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Missing JSON body'}), 400

        to_addr = data.get('to')
        subject = data.get('subject')
        body = data.get('body')
        security_level = int(data.get('securityLevel', 4))
        encrypt = data.get('encrypt', False)

        if not to_addr or not body:
            return jsonify({'error': 'Missing to or body fields'}), 400

        qumail_app.set_security_level(security_level)

        attachment_bytes = None
        attachment_name = None
        attachment = data.get('attachment')
        if attachment:
            b64data = attachment.get('b64')
            attachment_name = attachment.get('name')
            if b64data and attachment_name:
                try:
                    attachment_bytes = base64.b64decode(b64data)
                except Exception as e:
                    return jsonify({'error': f'Invalid attachment base64 data: {e}'}), 400

        qumail_app.send_secure_email(
            to_addr, subject, body.encode('utf-8'),
            attachment_bytes, attachment_name
        )
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/inbox', methods=['GET'])
def get_inbox():
    try:
        err = require_login()
        if err:
            return err

        emails = qumail_app.receive_secure_emails()
        processed_emails = []
        for email in emails:
            processed_email = {
                'from': email['from'],
                'subject': email['subject'],
                'body': email['body'].decode('utf-8') if isinstance(email['body'], bytes) else email['body'],
                'attachments': []
            }
            for att_name, att_data in email['attachments']:
                processed_email['attachments'].append({
                    'name': att_name,
                    'b64': base64.b64encode(att_data).decode('utf-8')
                })
            processed_emails.append(processed_email)

        return jsonify({'emails': processed_emails})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/keys/generate', methods=['POST'])
def generate_key():
    try:
        data = request.get_json()
        user_email = data.get('user_email')
        key_length = data.get('key_length', 32)

        key = qumail_app.km_client.get_quantum_key(user_email, key_length)
        if key:
            return jsonify({
                'success': True,
                'key': base64.b64encode(key).decode('utf-8'),
                'length': len(key)
            })
        else:
            return jsonify({'error': 'Failed to generate key'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
CORS(app, supports_credentials=True)

if __name__ == '__main__':
    app.run(debug=True, port=5001)