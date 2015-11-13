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
      testConfig((err, c) => {
        if (err) throw new Error(err);
        config = c
        req.state = config.state
        req.client = { id: 123 } // TODO?
        config.state.collections.auth.create({
          client: req.client.id,
          scope: [ 'bla' ],
          user: 13,
          code: code,
          redirectUri: req.body.redirect_uri,
          responseType: 'repTypeX',
          status: 'created'
        }).then(() => {
          done()
        }).catch((err) => {
          console.log('err', err)
          throw new Error(err)
        })
      })
    })
    afterEach(function(done) {
      config.state.connections.default._adapter.teardown(done)
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
          console.log('err', err)
          done()
        })
      })
    })
  })

})
