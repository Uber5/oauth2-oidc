"use strict";

const connect = require('connect'),
      simpleOauth2 = require('simple-oauth2')

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
      return this.oauth2.authCode.authorizeURL({
        redirect_uri: this.baseUrl + '/callback',
        scope: 'userinfo openid profile', // TODO: configurable?
        state: 's0meRandomStaksjeherwy',
      });
    }
  }
  initOAuth(config) {
    if (!config) throw new Error('missing oauth2 config');
    this.baseUrl = config.site
    this.oauth2 = simpleOauth2(config.oauth2)
  }
  get app() {
    return this._app;
  }
}

module.exports = TestClient
global.TestClient = TestClient
