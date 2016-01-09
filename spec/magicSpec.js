"use strict";

describe('magic link', function() {

  let oidc, config, client, user

  beforeEach(function(done) {
    oidc = new OAuth2OIDC({ state: {}, login_url: '/login', })
    buildTestConfig().then((c) => {
      config = c
      oidc.options.state = config.state
      Promise.resolve(buildAndSaveClient(config.state.collections, {})).then((savedClient) => {
        client = savedClient
        return buildAndSaveUser(config.state.collections)
      }).then((savedUser) => {
        user = savedUser
        done()
      })
    })
  })

  afterEach(function(done) {
    config.state.connections.default._adapter.teardown(function(err) {
      expect(err).toBeFalsy()
      done()
    })
  })

  describe('client without "magiclink" scope', function() {
    it('disallows creation of magiclink', function(done) {
      express().use(oidc.magickey()).handle(createRequest({
        headers: {
          authorization: getBasicClientAuthHeader(client)
        }
      }), createResponse(), (err) => {
        expect(err).toBeTruthy()
        expect(err).toMatch(/scope magiclink required/)
        done()
      })
    })
  })

  describe('client with "magiclink" scope', function() {
    let keyRequest
    beforeEach(function(done) {
      keyRequest = createRequest({
        headers: {
          authorization: getBasicClientAuthHeader(client)
        },
        body: {
          sub: user.sub,
          redirect_uri: client.redirect_uris[0],
          scope: 'userinfo,openid'
        }
      })
      client.scope = [ 'magiclink' ]
      client.save().then(done)
    })
    it('allows creation of magiclink', function(done) {
      const response = createResponse()
      express().use(oidc.magickey()).handle(keyRequest, response, (err) => {
        expect(err).toBeFalsy()
        const data = response._getData()
        expect(data.key).not.toBeFalsy()
        done()
      })
    })
    describe('with magickey', function() {
      let key, openRequest
      beforeEach(function(done) {
        const keyResponse = createResponse()
        express().use(oidc.magickey()).handle(keyRequest, keyResponse, (err) => {
          expect(err).toBeFalsy()
          const data = keyResponse._getData()
          key = data.key
          openRequest = createRequest({
            query: {
              key: key
            }
          })
          done()
        })
      })
      it('allows using the magickey', function(done) {
        const response = createResponse()
        express().use(oidc.magicopen()).handle(openRequest, response, (err) => {
          expect(err).toBeFalsy()
          expect(response.statusCode).toBe(302)
          done()
        })
      })
      it('does not allow the key twice', function(done) {
        express().use(oidc.magicopen()).handle(openRequest, createResponse(), (err) => {
          expect(err).toBeFalsy()
          const secondResponse = createResponse()
          console.log('key consumed, key', key)
          express().use(oidc.magicopen()).handle(createRequest({
            query: {
              key: key
            }
          }), secondResponse, (err2) => {
            expect(err2).toBeTruthy()
            expect(err2.error_description).toMatch(/expired/)
            done()
          })
        })
      })
    })
  })

})

