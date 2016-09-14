'use strict';

const urlParse = require('url-parse'),
    debug = require('debug')('oauth2-oidc')

describe('implicit flow', function() {
  let oidc

  const state = () => oidc.options.state

  beforeEach(function(done) {
    getState()
    .then(state => new OAuth2OIDC({ state, login_url: '/login' }))
    .then(o => {
      oidc = o
      done()
    })
    .catch(err => { console.log('implicit flow, beforeEach, error', err); done(err) })
  })

  describe('when client allows it', function() {
    let app, client, req
    beforeEach(function(done) {
      Promise.resolve(buildAndSaveClient(state().collections, {
        implicitFlow: true
      })).then((savedClient) => {
        client = savedClient
        done()
      }).catch(err => done(err))
    })
    describe('on correct authorization request', function() {
      const requestState = Math.random().toString()
      beforeEach(function(done) {
        req = createRequest({
          query: {
            response_type: 'token',
            client_id: client.key,
            redirect_uri: client.redirect_uris[0],
            scope: client.scope.join(','),
            state: requestState
          }
        })
        req.client = client
        req.session = {}
        app = express()
        app.use(oidc._useState())
        app.use(oidc._authorize())
        Promise.resolve(buildAndSaveUser(state().collections, { password: '123', passConfirm: '123' })).then((user) => {
          req.session.user = user._id
          done()
        }).catch((err) => {
          debug('buildAndSaveUser, err', err)
          throw err
        })
      })
      const res = createResponse()
      it('provides an access_token', function(done) {
        app.handle(req, res, (err) => {
          expect(err).toBeFalsy()
          expect(res.statusCode).toEqual(302)
          const url = res._getRedirectUrl()
          expect(url).toMatch(client.redirect_uris[0])
          const queryString = urlParse(url).hash.replace('#', '')
          const data = urlParse.qs.parse(queryString)
          expect(data.access_token).toBeTruthy()
          expect(data.expires_in).toBeTruthy()
          expect(data.token_type).toBeTruthy()
          expect(data.state).toEqual(requestState)
          done()
        })
      })
    })

  })

  describe('when client does not allow it', function() {
    let app, client, req
    beforeEach(function(done) {
      Promise.resolve(buildAndSaveClient(state().collections, {
        // implicitFlow: false
      })).then((savedClient) => {
        client = savedClient
        done()
      })
    })
    describe('on correct authorization request', function() {
      const requestState = Math.random().toString()
      beforeEach(function(done) {
        req = createRequest({
          query: {
            response_type: 'token',
            client_id: client.key,
            redirect_uri: client.redirect_uris[0],
            scope: client.scope.join(','),
            state: requestState
          }
        })
        req.client = client
        req.state = state()
        app = express()
        app.use(oidc._authorize())
        done()
      })
      it('rejects the request', function(done) {
        app.handle(req, createResponse(), (err) => {
          expect(err).not.toBeFalsy()
          expect(err.error).toEqual('unauthorized_client')
          done()
        })
      })
    })
  })

})
