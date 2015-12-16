"use strict";

describe('magic link', function() {

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

  describe('client without "magiclink" scope', function() {
    let client
    beforeEach(function(done) {
      Promise.resolve(buildClient({
      })).then((unsavedClient) => {
        return config.state.collections.client.create(unsavedClient)
      }).then((savedClient) => {
        client = savedClient
        done()
      })
    })
    it('disallows creation of magiclink', function(done) {
      express().use(oidc.magickey()).handle(createRequest({
        headers: {
          authorization: getBasicClientAuthHeader(client)
        }
      }), createResponse(), (err) => {
        expect(err).toBeTruthy()
        console.log('err', err)
        expect(err).toMatch(/scope magiclink required/)
        done()
      })
    })
  })

})

