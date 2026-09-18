from flask import Flask, request, jsonify
import requests as req

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <h1>SSRF Lab</h1>
    <p>Vulnerable endpoint: /fetch?url=http://example.com</p>
    <p>Try accessing internal services:</p>
    <ul>
        <li>http://localhost:5000/internal</li>
        <li>http://127.0.0.1:5000/internal</li>
        <li>file:///etc/passwd</li>
    </ul>
    '''

@app.route('/fetch')
def fetch():
    url = request.args.get('url', 'http://example.com')
    
    try:
        # Vulnerable SSRF - fetches user-supplied URL with no validation
        resp = req.get(url, timeout=10)
        return resp.text
    except req.Timeout:
        return "Request timed out", 408
    except Exception as e:
        return str(e), 500

@app.route('/internal')
def internal():
    """Internal endpoint that should not be accessible"""
    return jsonify({
        "message": "Internal endpoint accessed!",
        "secret": "super_secret_data_12345",
        "credentials": {
            "admin": "admin123",
            "db_password": "p@ssw0rd"
        }
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
