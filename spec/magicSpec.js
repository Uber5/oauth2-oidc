"use strict";

describe('magic link', function() {

  let oidc, config, client, user

  beforeEach(function(done) {
    oidc = new OAuth2OIDC({ state: {}, login_url: '/login', })
    buildTestConfig().then((c) => {
      config = c
      oidc.options.state = config.state
      Promise.resolve(buildClient({
      })).then((unsavedClient) => {
        return config.state.collections.client.create(unsavedClient)
      }).then((savedClient) => {
        client = savedClient
        return config.state.collections.user.create(buildUser())
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
    let request, response
    beforeEach(function(done) {
      request = createRequest({
        headers: {
          authorization: getBasicClientAuthHeader(client)
        },
        body: {
          sub: user.sub,
          redirect_uri: client.redirect_uris[0],
          scope: 'userinfo,openid'
        }
      })
      response = createResponse()
      client.scope = [ 'magiclink' ]
      client.save().then(done)
    })
    it('allows creation of magiclink', function(done) {
      express().use(oidc.magickey()).handle(request, response, (err) => {
        console.log('err', err)
        expect(err).toBeFalsy()
        const data = response._getData()
        console.log('response', data)
        done()
      })
    })
  })

})

