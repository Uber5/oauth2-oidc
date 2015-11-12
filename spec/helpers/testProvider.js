"use strict";

const express = require('express'),
      OAuth2OIDC = require('../..'),
      validate = require('jsonschema').validate,
      debug = require('debug')('oauth2-oidc'),
      bodyParser = require('body-parser'),
      session = require('express-session'),
      crypto = require('crypto'),
      bcrypt = require('bcryptjs')

function userHasPassword(user, pwd) {
  return bcrypt.compareSync(pwd, user.password)
}

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

    app.post('/user/token', oauth2oidc.token())

    app.get('/login', (req, res) => {
      res.render('login.html')
    })

    app.post('/login', (req, res, next) => {
      const username = req.body.username
      debug('POST /login, body', username, req.body)
      config.state.collections.user.findOne({ sub: username })
      .then((user) => {
        debug('POST /login', user)
        if (!user) {
          return res.render('login.html', { flash: `user ${ username } not found.` })
        }
        if (userHasPassword(user, req.body.password)) {
          req.session.user = user.id
          return res.redirect(req.session.return_url || '/')
        } else {
          return res.render('login.html', { flash: 'Password incorrect.' })
        }
      }).catch((err) => {
        debug('POST /login, err', err)
        return next(err)
      })
    })

    // error handling
    function testErrorHandler(err, req, res, next) {
      debug('testErrorHandler', err)
      if (res.headersSent) {
        debug('error handling, headers sent already')
        return next(err)
      }
      res.status(err.status || 500)
      res.render('error.html', { error: err.message || JSON.stringify(err) })
    }
    app.use(testErrorHandler)

    this._app = app
  }
  get app() {
    return this._app
  }
}

module.exports = TestProvider
global.TestProvider = TestProvider
