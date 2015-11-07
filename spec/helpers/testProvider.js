"use strict";

const express = require('express'),
      OAuth2OIDC = require('../..'),
      validate = require('jsonschema').validate,
      debug = require('debug')('oauth2-oidc'),
      session = require('express-session'),
      crypto = require('crypto')

class TestProvider {
  constructor(config) {
    const app = express()
    const oauth2oidc = new OAuth2OIDC(config)
    app.use(session({
      secret: crypto.randomBytes(12).toString('base64')
    }))
    app.use('/user/authorize', oauth2oidc.auth())
    this._app = app
  }
  get app() {
    return this._app
  }
}

module.exports = TestProvider
global.TestProvider = TestProvider
