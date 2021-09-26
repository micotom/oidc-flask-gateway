import os
import logging
from flask import Flask, jsonify
from flask_oidc import OpenIDConnect

auth_server_port = os.getenv('AUTH_SERVER_PORT')
app = Flask(__name__)
app.config.update({
    'SECRET_KEY': 'secret',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': './keycloak.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': f'http://localhost:{auth_server_port}/flask',
    'OIDC_CALLBACK_ROUTE': '/oidc_callback',
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post',
    'OIDC_CLOCK_SKEW': 560,
    'OIDC_TOKEN_TYPE_HINT': 'access_token',
    'OIDC_VALID_ISSUERS': ['http://localhost:8080/auth/realms/flask']
})
oidc = OpenIDConnect(app)

@app.before_first_request
def setup_logging():
    if not app.debug:
        # In production mode, add log handler to sys.stderr.
        app.logger.addHandler(logging.StreamHandler())
        app.logger.setLevel(logging.INFO)

@app.route('/')
def welcome():
    return jsonify({'api_status': 'active'})

@app.route('/api')
@oidc.accept_token(require_token=True)
def api():
    preferred_name = oidc.user_getfield('preferred_name')
    return jsonify({'user_status': 'authorized', 'user': f'{preferred_name}'})

@app.route('/auth')
@oidc.require_login
def auth():
    info = oidc.user_getinfo(['preferred_username', 'email', 'sub'])
    username = info.get('preferred_username')
    email = info.get('email')
    user_id = info.get('sub')
    return f'Hello, {username}!'
    '''
    if user_id in oidc.credentials_store:
        return f'Hello, {username}!'
        try:
            from oauth2client.client import OAuth2Credentials
            access_token = OAuth2Credentials.from_json(oidc.credentials_store[user_id]).access_token
            headers = {'Authorization': f'Bearer {access_token}'}
            access_like_this = requests.get('http://localhost:5001/api', headers=headers).text
        except:
            access_like_this = "we failed"
        return f'Hello, api: {access_like_this} <a href="/">Return</a>'
    else:
        return f'Ops, <a href="/">Return</a>'
    '''

@app.route('/oidc_callback')
@oidc.custom_callback
def redirect(data):
    return "Foo!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=os.getenv('PORT'))