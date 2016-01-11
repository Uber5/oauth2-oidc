'use strict';

const qs = require('url-parse').qs

describe('implicit flow', function() {
  let oidc, config

  beforeEach(function(done) {
    oidc = new OAuth2OIDC({ state: {}, login_url: '/login', })
    buildTestConfig().then((c) => {
      config = c
      oidc.options.state = config.state
      done()
    })
  })

  afterEach(function(done) {
    config.state.connections.default._adapter.teardown(function(err) {
      expect(err).toBeFalsy()
      done()
    })
  })

  describe('when client allows it', function() {
    let app, client, req
    beforeEach(function(done) {
      Promise.resolve(buildAndSaveClient(config.state.collections, {
        implicitFlow: true
      })).then((savedClient) => {
        client = savedClient
        done()
      })
    })
    describe('on correct authorization request', function() {
      const state = 'some-state'
      beforeEach(function(done) {
        req = createRequest({
          query: {
            response_type: 'token',
            client_id: client.key,
            redirect_uri: client.redirect_uris[0],
            scope: client.scope.join(','),
            state: state
          }
        })
        req.client = client
        req.session = {}
        // req.state = config.state
        app = express()
        app.use(oidc._useState())
        app.use(oidc._authorize())
        Promise.resolve(buildAndSaveUser(config.state.collections, { password: '123', passConfirm: '123' })).then((user) => {
          req.session.user = user
          done()
        }).catch((err) => {
          console.log('buildAndSaveUser, err', err)
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
          const data = qs.parse(url)
          expect(data.access_token).toBeTruthy()
          expect(data.expires_in).toBeTruthy()
          expect(data.token_type).toBeTruthy()
          expect(data.state).toEqual(state)
          done()
        })
      })
    })

  })

  describe('when client does not allow it', function() {
    let app, client, req
    beforeEach(function(done) {
      Promise.resolve(buildAndSaveClient(config.state.collections, {
        // implicitFlow: false
      })).then((savedClient) => {
        client = savedClient
        done()
      })
    })
    describe('on correct authorization request', function() {
      const state = 'some-state'
      beforeEach(function(done) {
        req = createRequest({
          query: {
            response_type: 'token',
            client_id: client.key,
            redirect_uri: client.redirect_uris[0],
            scope: client.scope.join(','),
            state: state
          }
        })
        req.client = client
        req.state = config.state
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
