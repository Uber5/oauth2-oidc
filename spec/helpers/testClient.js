"use strict";

const connect = require('connect'),
      simpleOauth2 = require('simple-oauth2'),
      validate = require('jsonschema').validate,
      debug = require('debug')('oauth2-oidc')

const oauth2ConfigSchema = {
  id: 'oauth2 config properties',
  type: "object",
  clientID: { type: 'string' },
  required: [ 'clientID', 'clientSecret', 'site', 'tokenPath', 'authorizationPath' ]
};

class TestClient {
  constructor(config) {
    this.config = config || {};
    const app = connect();
    app.use('/login', (req, res) => {
      res.writeHead(302, { location: this._authorizeUriFn() })
      res.end()
    })
    app.use('/', (req, res) => {
      res.setHeader('content-type', 'text/html')
      res.end('Hello, please <a href="/login">log in</a>.')
    });
    this._app = app;
    this._authorizeUriFn = () => {
      const uri = this.oauth2.authCode.authorizeURL({
        redirect_uri: this._baseUrl + '/callback',
        scope: 'userinfo openid profile', // TODO: configurable?
        state: 's0meRandomStaksjeherwy',
      })
      debug(`_authorizeUriFn, uri=${ uri }`)
      return uri
    }
  }
  initOAuth(config) {
    if (!config) throw new Error('missing oauth2 config');
    const errors = validate(config, oauth2ConfigSchema).errors;
    if (errors.length) throw new Error(`invalid config: ${ errors }`);
    this.oauth2 = simpleOauth2(config)
  }
  set baseUrl (url) {
    console.log('setting baseUrl to ' + url)
    this._baseUrl = url
  }
  get app() {
    return this._app;
  }
}

module.exports = TestClient
global.TestClient = TestClient
