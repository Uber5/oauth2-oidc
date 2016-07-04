"use strict";

describe('token', function() {

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
      req.state = config.state
      const res = createResponse()
      oidc._getClientOnTokenRequest()(req, res, function(err) {
        expect(err).toBeTruthy()
        expect(err.error).toEqual('invalid_request')
        expect(err.error_description).toMatch(/missing auth/)
        done()
      })
    })
  })

  describe('credentials in body', function() {
    let req, res, client
    beforeEach(function(done) {
      Promise.resolve(buildAndSaveClient(config.state.collections, {})).then((savedClient) => {
        client = savedClient
        req = createRequest({
          body: {
            client_id: client.key,
            client_secret: client.secret
          }
        })
        req.state = config.state
        res = createResponse()
        done()
      })
    })
    describe('by default', function() {
      it('results in 401', function(done) {
        oidc._getClientOnTokenRequest()(req, res, function(err) {
          expect(err).toBeTruthy()
          expect(err.error_description).toMatch(/missing authorization header/)
          done()
        })
      })
    })
    describe('when permitted', function() {
      beforeEach(function(done) {
        client.allowClientCredentialsInBody = true
        client.save().then(savedClient => done())
      })
      it('is okay', function(done) {
        oidc._getClientOnTokenRequest()(req, res, function(err) {
          expect(err).toBeFalsy()
          done()
        })
      })
    })
  })

  describe('client that does not enforce authorization on token request', function() {
    // See notes on https://tools.ietf.org/html/rfc6749#section-4.1.3
    let req, res, client
    beforeEach(function(done) {
      Promise.resolve(buildAndSaveClient(config.state.collections, {
        enforceAuthOnTokenRequest: false
      })).then((savedClient) => {
        client = savedClient
        req = createRequest({
          body: {
            client_id: client.key
          }
        })
        req.state = config.state
        res = createResponse()
        done()
      }).catch((err) => {
        debug('err', err)
      })
    })
    it('allows token request with client_id only', function(done) {
      oidc._getClientOnTokenRequest()(req, res, function(err) {
        expect(err).toBeFalsy()
        done()
      })
    })
  })

  describe('on invalid client credentials', function() {
    let req, res, client
    beforeEach(function(done) {
      req = createRequest({})
      res = createResponse()
      req.state = config.state
      Promise.resolve(buildAndSaveClient(config.state.collections)).then((savedClient) => {
        client = savedClient
        done()
      })
    })
    it('rejects if there is no "authorization" header', function(done) {
      oidc._getClientOnTokenRequest()(req, res, function(err) { // TODO: duplicate spec
        expect(err).toBeTruthy()
        expect(err.error).toBe('invalid_request')
        expect(err.error_description).toMatch(/missing auth/)
        done()
      })
    })
    it('rejects invalid authorization header', function(done) {
      req.headers = { authorization: 'bla' }
      oidc._getClientOnTokenRequest()(req, res, function(err) {
        expect(err).toBeTruthy()
        expect(err.error).toBe('invalid_request')
        expect(err.error_description).toMatch(/expected/)
        done()
      })
    })
    it('rejects non-existent client in header', function(done) {
      req.headers.authorization = getBasicClientAuthHeader({ key: 'doesnt-exist', secret: '1234' })
      oidc._getClientOnTokenRequest()(req, res, function(err) {
        expect(err).toBeTruthy()
        expect(err.error).toBe('invalid_request')
        expect(err.error_description).toMatch(/not found/)
        done()
      })
    })
    it('rejects invalid client secret', function(done) {
      req.headers.authorization = getBasicClientAuthHeader({ key: client.key, secret: 'incorrect secret' })
      oidc._getClientOnTokenRequest()(req, res, function(err) {
        expect(err).toBeTruthy()
        expect(err.error).toBe('invalid_request')
        expect(err.error_description).toMatch(/incorrect/)
        done()
      })
    })
  })

  describe('consuming client code', function() {
    let req, res, code
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
      req.state = config.state
      req.client = { id: nextId() }
      config.state.collections.auth.create({
        client: req.client.id,
        scope: [ 'bla' ],
        user: 13,
        code: code,
        redirectUri: req.body.redirect_uri,
        responseType: 'repTypeX',
        status: 'created'
      }).then((auth) => {
        done()
      }).catch((err) => {
        debug('err', err)
        expect(err).toBeFalsy()
      })
    })
    it('retrieves the auth by code', function(done) {
      oidc._consumeClientCode(req).then(() => {
        expect(req.auth).not.toBe(undefined)
        done()
      })
    })
    it('fails when retrieving the same code twice', function(done) {
      oidc._consumeClientCode(req).then(() => {
        oidc._consumeClientCode(req).catch((err) => {
          expect(err).not.toBe(undefined)
          done()
        })
      })
    })
  })

  describe('via password', function() {
    const password = 'TopSecret'
    let client, user, app, req, res
    function buildClientAndUser(isPasswordFlowAllowed, done) {
      Promise.resolve(buildClient({
        passwordFlow: isPasswordFlowAllowed
      })).then((unsavedClient) => {
        return config.state.collections.client.create(unsavedClient)
      }).then((newClient) => {
        if (!newClient) throw new Error('no client created');
        client = newClient
        return buildUser({
          password: password,
          passConfirm: password
        })
      }).then((unsavedUser) => {
        return config.state.collections.user.create(unsavedUser)
      }).then((newUser) => {
        user = newUser
        app = express()
        app.use(oidc.token())
        req = createRequest({
          body: {
            grant_type: 'password',
            client_id: client.key,
            client_secret: client.secret,
            username: user.sub,
            password: password
          }
        })
        res = createResponse()
        done()
      })
    }
    describe('when password access is not allowed', function() {
      beforeEach(function(done) {
        buildClientAndUser(false, done)
      })
      it('fails', function(done) {
        app.handle(req, res, (err) => {
          expect(err).toBeTruthy()
          done()
        })
      })
    })
    describe('when password access is allowed', function() {
      beforeEach(function(done) {
        buildClientAndUser(true, done)
      })
      it('provides an access token', function(done) {
        app.handle(req, res, (err) => {
          console.log('err, res._getData()', err, res._getData())
          expect(err).toBeFalsy()
          done()
        })
      })
      it('fails on invalid client credentials', function(done) {
        req.body.client_secret = 'invalid'
        app.handle(req, res, (err) => {
          expect(err).toBeTruthy()
          done()
        })
      })
      it('fails on invalid user credentials', function(done) {
        req.body.password = 'invalid'
        app.handle(req, res, (err) => {
          expect(err).toBeTruthy()
          done()
        })
      })
    })
  })

  describe('logging out', function() {
    let user, access, app, req, res
    beforeEach(function(done) {
      buildUsableAccessToken({ config: config }, (err, result) => {
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
    describe('after logging out', function() {
      beforeEach(function(done) {
        express().use(oidc.logout()).handle(createRequest({
          headers: {
            authorization: `Bearer ${ access.token }`
          }
        }), createResponse(), (err) => {
          expect(err).toBeFalsy()
          done()
        })
      })
      it('denies userinfo', function(done) {
        app.handle(req, res, function(err) {
          expect(err).toBeTruthy()
          expect(err.status).toEqual(401)
          // expect(err.error_description).toMatch(/invalid or expired/) // TODO
          done()
        })
      })
      it('denies refreshing', function(done) {
        done() // TODO
      })
    })
    describe('before logging out', function() {
      it('allows querying user info', function(done) {
        done() // TODO: duplicate to scenario 'expiring'
      })
    })
  })

  describe('expiring', function() {
    let user, access, app, req, res
    beforeEach(function(done) {
      buildUsableAccessToken({ config: config }, (err, result) => {
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
    it('allows querying userinfo with access token', function(done) {
      app.handle(req, res, function(err) {
        if (err) console.log('err 320', err.stack);
        expect(err).toBeFalsy()
        done()
      })
    })
    describe('when more than expiry time has passed', function() {
      function addMillisToDate(date, millis) {
        return new Date(date.getTime() + millis)
      }
      beforeEach(function(done) {
        // tweak 'createdAt' so that token appears expired
        access.createdAt = addMillisToDate(
          access.createdAt,
          -1 * (60 * 60 * 1000 + 1) /* subtract 1 hour plus one ms */
        )
        access.save().then(done)
      })
      it('fails with http code 401', function(done) {
        app.handle(req, res, function(err) {
          expect(err).toBeTruthy()
          expect(err.status).toEqual(401)
          done()
        })
      })
    })
  })

  describe('refresh_token', function() {
    let user, client, access, app, req, res
    beforeEach(function(done) {
      // get an access token first
      buildUsableAccessToken({ config: config }, (err, result) => {
        expect(err).toBeFalsy()
        config = result.config
        user = result.user
        access = result.access
        client = result.client
        app = express()
        app.use(oidc.token())
        // request a refresh token by using client credentials
        req = createRequest({
          headers: {
            authorization: getBasicClientAuthHeader(client)
          },
          body: {
            grant_type: 'refresh_token',
            refresh_token: access.refresh_token
          }
        })
        req.state = config.state
        oidc.options.state = config.state
        res = createResponse()
        done()
      })
    })
    it('issues a usable access token for a refresh token', function(done) {
      app.handle(req, res, function(err) {
        expect(err).toBeFalsy()
        const data = res._getData()
        expect(data.access_token).toBeTruthy()
        expect(data.refresh_token).toBeTruthy()
        expect(data.expires_in).toBeTruthy()
        expect(data.token_type).toBeTruthy()
        done()
      })
    })
    describe('for different client', function() {
      let client2
      beforeEach(function(done) {
        Promise.resolve(buildAndSaveClient(config.state.collections)).then((client) => {
          client2 = client
          done()
        })
      })
      it('rejects getting a refresh token', function(done) {
        req.headers.authorization = getBasicClientAuthHeader(client2)
        app.handle(req, res, function(err) {
          expect(err).toBeTruthy()
          expect(err.error).toEqual('invalid_token')
          expect(err.error_description).toMatch(/not belong to client/)
          done()
        })
      })
    })
  })

})
