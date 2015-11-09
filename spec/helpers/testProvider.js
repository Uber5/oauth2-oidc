"use strict";

const express = require('express'),
      OAuth2OIDC = require('../..'),
      validate = require('jsonschema').validate,
      debug = require('debug')('oauth2-oidc'),
      bodyParser = require('body-parser'),
      session = require('express-session'),
      crypto = require('crypto')

class TestProvider {
  constructor(config) {
    const app = express()
    const oauth2oidc = new OAuth2OIDC(config)

    app.engine('html', require('ejs').renderFile)
    app.set('view engine', 'ejs')
    app.set('views', './examples/views')
    app.use(bodyParser.urlencoded({ extended: true }))
    app.use(session({
      resave: false,
      saveUninitialized: false,
      // you will want a secret that does not change on every (re)start in
      // production, this is just good for testing:
      secret: crypto.randomBytes(12).toString('base64')
    }))

    app.all('/user/authorize', oauth2oidc.auth())

    app.get('/login', (req, res) => {
      res.render('login.html')
    })

    app.post('/login', (req, res) => {
      console.log('POST /login, body', req.body)
      res.render('fake-login.html')
    })

    this._app = app
  }
  get app() {
    return this._app
  }
}

module.exports = TestProvider
global.TestProvider = TestProvider
