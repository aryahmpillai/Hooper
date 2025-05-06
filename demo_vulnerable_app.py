#!/usr/bin/env python3
"""
Demo Flask application with intentional open redirect vulnerabilities
for testing the Hopper scanner.
"""

from flask import Flask, redirect, request

app = Flask(__name__)

@app.route('/')
def index():
    return """
    <h1>Demo Vulnerable App for Hopper Testing</h1>
    <p>This application has several endpoints with open redirect vulnerabilities:</p>
    <ul>
        <li><a href="/redirect?url=https://example.com">Basic Redirect</a></li>
        <li><a href="/login?next=https://example.com">Login Redirect</a></li>
        <li><a href="/go?to=https://example.com">Go To</a></li>
        <li><a href="/masked?destination=https://example.com">Masked Redirect</a></li>
        <li><a href="/js-redirect?location=https://example.com">JavaScript Redirect</a></li>
        <li><a href="/meta-redirect?target=https://example.com">Meta Refresh Redirect</a></li>
    </ul>
    """

@app.route('/redirect')
def basic_redirect():
    # Basic open redirect vulnerability
    redirect_url = request.args.get('url', '/')
    return redirect(redirect_url)

@app.route('/login')
def login_redirect():
    # Common post-login redirect vulnerability
    next_url = request.args.get('next', '/')
    return redirect(next_url)

@app.route('/go')
def go_to():
    # Another common redirect parameter
    to_url = request.args.get('to', '/')
    return redirect(to_url)

@app.route('/masked')
def masked_redirect():
    # Masked parameter name
    destination = request.args.get('destination', '/')
    return redirect(destination)

@app.route('/js-redirect')
def js_redirect():
    # JavaScript-based redirect
    location = request.args.get('location', '/')
    return f"""
    <html>
    <head>
        <script>
            window.location = "{location}";
        </script>
    </head>
    <body>
        <p>Redirecting to {location}...</p>
    </body>
    </html>
    """

@app.route('/meta-redirect')
def meta_redirect():
    # Meta refresh redirect
    target = request.args.get('target', '/')
    return f"""
    <html>
    <head>
        <meta http-equiv="refresh" content="0;url={target}">
    </head>
    <body>
        <p>Redirecting to {target}...</p>
    </body>
    </html>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)