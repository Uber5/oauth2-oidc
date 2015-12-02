"use strict";

describe('auth', function() {

  let oidcConfig, oidc

  beforeEach(function(done) {
    testConfig(function(err, config) {
      oidcConfig = config
      oidc = new OAuth2OIDC(config);
      done()
    })
  })

  afterEach(function(done) {
    // console.log('oidcConfig.state', oidcConfig.state)
    oidcConfig.state.connections.default._adapter.teardown(done)
  })

  describe('_validateAuth', function() {

    it('fails without params', function(done) {
      oidc._validateAuth(createRequest({}), createResponse(), function(err) {
        expect(err).not.toBe(undefined);
        done();
      });
    });

    it('succeeds with required params', function(done) {
      oidc._validateAuth(createRequest({
        query: {
          response_type: 'x',
          client_id: '123',
          scope: 'bla',
          redirect_uri: 'y',
        }
      }), createResponse(), function(err) {
        expect(err).toBe(undefined);
        done();
      });
    });

  });

  describe('_verifyRedirectUri', function() {
    it('succeeds for valid redirect_uri', function(done) {
      const req = createRequest({
        query: {
          redirect_uri: 'https://my.host.com/callback?p1=123',
        }
      })
      req.client = {
        redirect_uris: [ 'https://my.host.com' ]
      }
      oidc._verifyRedirectUri()(req, createResponse(), function(err) {
        expect(err).toBeFalsy()
        done()
      })
    })
    it('fails for invalid redirect_uri', function(done) {
      const req = createRequest({
        query: {
          redirect_uri: 'https://ANOTHER.host.com/callback?p1=123',
        }
      })
      req.client = {
        redirect_uris: [ 'https://my.host.com' ]
      }
      oidc._verifyRedirectUri()(req, createResponse(), function(err) {
        expect(err).toBeTruthy()
        done()
      })
    })
  })

  describe('_authorize', function() {
    it('fails with invalid response_type', function(done) {
      oidc._authorize()(createRequest({
        query: {
          response_type: 'x',
          client_id: '123',
          scope: 'bla',
          redirect_uri: 'y'
        }
      }), createResponse(), function(err) {
        expect(err.error_description).toMatch(/Invalid or unsupported response_type/)
        done()
      })
    })
  })
});
