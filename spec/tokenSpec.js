"use strict";

describe('token', function() {

  let oidc

  beforeEach(function() {
    oidc = new OAuth2OIDC({ state: {}, login_url: '/login', })
  })

  describe('extracting client credentials from header', function() {

    it('fails if it does not start with "Basic "', function() {
      expect(oidc._extractCredentialsFromHeaderValue('bla').error).toMatch(/expected "Basic" auth/)
    })

    it('fails if basic auth header has wrong format', function() {
      expect(oidc._extractCredentialsFromHeaderValue('Basic bla').error).toMatch(/unable to extract cred/)
    })

    it('succeeds for key:secret (base64 encoded)', function() {
      const result = oidc._extractCredentialsFromHeaderValue('Basic aWQ6a2V5')
      expect(result.error).toBe.undefined
      expect(result.client_id).toEqual('id')
      expect(result.secret).toEqual('key')
    })

    it('verifies presence of authorization on token request', function(done) {
      const req = createRequest({})
      const res = createResponse()
      oidc._getClientOnTokenRequest()(req, res, function(err) {
        expect(res.statusCode).toBe(401)
        expect(JSON.stringify(res._getData())).toMatch(/missing authorization header/)
        done()
      })
    })
  })

  describe('consuming client code', function() {
    let config, req, res, code
    beforeEach(function(done) {
      code = '12345'
      req = createRequest({
        body: {
          grant_type: 'authorization_code',
          code: code,
          redirect_uri: 'http://test.com/callback',
          client_id: 'client887'
        }
      })
      res = createResponse()
      new Promise((resolve, reject) => {
        testConfig((err, c) => {
          if (err) return reject(err);
          resolve(c)
        })
      }).then((c) => {
        config = c
        req.state = config.state
        req.client = { id: nextId() }
        return config.state.collections.auth.create({
          client: req.client.id,
          scope: [ 'bla' ],
          user: 13,
          code: code,
          redirectUri: req.body.redirect_uri,
          responseType: 'repTypeX',
          status: 'created'
        })
      }).then((auth) => {
        done()
      }).catch((err) => {
        debug('err', err)
        expect(err).toBeFalsy()
      })
    })
    afterEach(function(done) {
      config.state.connections.default._adapter.teardown(function(err) {
        expect(err).toBeFalsy()
        done()
      })
    })
    it('retrieves the auth by code', function(done) {
      oidc._consumeClientCode()(req, res, function(err) {
        expect(err).toBe(undefined)
        expect(res.statusCode).toBe(200)
        expect(req.auth).not.toBe(undefined)
        done()
      })
    })
    it('fails when retrieving the same code twice', function(done) {
      oidc._consumeClientCode()(req, res, function(err) {
        expect(err).toBe(undefined)
        oidc._consumeClientCode()(req, res, function(err) {
          expect(err).not.toBe(undefined)
          debug('errxx', err)
          done()
        })
      })
    })
  })

  describe('expiring', function() {
    let basetime, config, user, access, app, req, res
    beforeEach(function(done) {
      // jasmine.clock().install()
      buildUsableAccessToken({}, (err, result) => {
        console.log('err2', err)
        expect(err).toBeFalsy()
        config = result.config
        user = result.user
        access = result.access
        app = express()
        app.use(oidc.userinfo())
        req = createRequest({
          headers: {
            authorization: `Bearer ${ access.token }`
          }
        })
        res = createResponse()
        oidc.options.state = config.state
        done()
      })
    })
    afterEach(function(done) {
      // jasmine.clock().uninstall()
      config.state.connections.default._adapter.teardown(done)
    })
    it('allows querying userinfo with access token', function(done) {
      // jasmine.clock().tick(60 * 60 * 1000 - 10) // one hour plus minus some ticks
      app.handle(req, res, function(err) {
        // expect(err).toBeFalsy()
        done()
      })
    })
    describe('when more than expiry time has passed', function() {
      it('fails with http code 401', function(done) {
        // jasmine.clock().tick(60 * 60 * 1000 + 1) // one hour plus one tick
        app.handle(req, res, function(err) {
          expect(err).toBeTruthy()
          done()
        })
      })
    })
  })

})
