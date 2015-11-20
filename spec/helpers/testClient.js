"use strict";

const express = require('express'),
      session = require('express-session'),
      bodyParser = require('body-parser'),
      request = require('request'),
      crypto = require('crypto'),
      simpleOauth2 = require('simple-oauth2'),
      validate = require('jsonschema').validate,
      debug = require('debug')('oauth2-oidc'),
      createMagicLink = require('../../examples/magic-link').createMagicLink

const oauth2ConfigSchema = {
  id: 'oauth2 config properties',
  type: "object",
  clientID: { type: 'string' },
  required: [ 'clientID', 'clientSecret', 'site', 'tokenPath', 'authorizationPath' ]
};

class TestClient {
  constructor(config) {
    this.config = config || {};
    debug('TextClient constructor, this.config', this.config)
    const app = express();
    app.use(session({
      resave: false,
      saveUninitialized: false,
      secret: crypto.randomBytes(12).toString('base64')
    }))
    app.use(bodyParser.urlencoded({ extended: true }))
    app.use('/login', (req, res) => {
      res.writeHead(302, { location: this._authorizeUriFn() })
      res.end()
    })
    app.get('/', (req, res) => {
      res.setHeader('content-type', 'text/html')
      res.end('<html><body><p>Hello, please <a href="/login">log in</a>.'
        + ' Or, send me a <a href="/magiclink">magic link</a>.</p></body></html>')
    });
    app.get('/callback', (req, res, next) => {
      const code = req.query.code
      this.oauth2.authCode.getToken({
        code: code,
        redirect_uri: this.callbackUrl
      }, (err, result) => {
        if (err) return res.end('error: ' + JSON.stringify(err));
        const token = this.oauth2.accessToken.create(result)
        req.session.token = token
        debug('keeping token, redirecting')
        res.redirect('/my-profile')
      })
    })
    app.get('/my-profile', (req, res, err) => {
      const token = req.session.token
      if (!token) return res.redirect('/login');
      debug('getting userInfo', token)
      const getUserinfo = (token, callback) => {
        debug('this.oauthConfig', this.oauthConfig)
        request({
          url: this.oauthConfig.site + '/userinfo',
          headers: {
            authorization: `Bearer ${ token.token.access_token }`
          }
        }, (err, res, body) => {
          if (err) throw new Error(err);
          callback(err, body)
        })
      }
      getUserinfo(token, function(err, userinfo) {
        debug('userinfo', userinfo)
        const sub = JSON.parse(userinfo).sub
        res.send(`<html><body><p>Logged in as ${ sub }</p></body></html>`)
      })
    })
    app.get('/magiclink', (req, res, next) => {
      debug('req.headers', req.headers)
      res.setHeader('content-type', 'text/html')
      res.send('<html><body><h1>Send me a magic link</h1>'
        + '<form method="POST">'
        + '<input type="email" name="email" placeholder="Your email"/>'
        + '<input type="submit"/>'
        + '</form></body></html>')
    })
    app.post('/magiclink', (req, res, next) => {
      debug('magiclink', req.body)
      new Promise((resolve, reject) => {
        createMagicLink(this.oauthConfig, this.callbackUrl, req.body.email, (err, result) => {
          if (err) return reject(err);
          resolve(result)
        })
      }).then((result) => {
        debug('magiclink result', result)
        const link = this.oauthConfig.site + '/magicopen?key=' + encodeURIComponent(result.key)
        debug('magiclink, link', link)
        res.send('NEVER use this link *unless* in an email to the recipient! result: ' + JSON.stringify(result))
      }).catch((err) => {
        res.status(500).send('error: ' + JSON.stringify(err))
      })
    })
    this._app = app;
    this._authorizeUriFn = () => {
      const uri = this.oauth2.authCode.authorizeURL({
        redirect_uri: this.callbackUrl,
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
    this.oauthConfig = config
  }
  get callbackUrl() {
    return this._baseUrl + '/callback'
  }
  set baseUrl (url) {
    debug('setting baseUrl to ' + url)
    this._baseUrl = url
  }
  get app() {
    return this._app;
  }
}

module.exports = TestClient
global.TestClient = TestClient
