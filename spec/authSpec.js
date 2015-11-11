"use strict";

var httpMocks = require('node-mocks-http');

describe('auth', function() {

  function createRequest(query) {
    return httpMocks.createRequest({
      method: 'GET',
        url: '/whatever',
        query: query
    });
  };

  function createResponse() {
    return httpMocks.createResponse();
  };

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
        response_type: 'x',
        client_id: '123',
        scope: 'bla',
        redirect_uri: 'y',
      }), createResponse(), function(err) {
        expect(err).toBe(undefined);
        done();
      });
    });

  });

  describe('_authorize', function() {
    it('fails with invalid response_type', function(done) {
      oidc._authorize()(createRequest({
        response_type: 'x',
        client_id: '123',
        scope: 'bla',
        redirect_uri: 'y'
      }), createResponse(), function(err) {
        expect(err).toMatch(/Invalid or unsupported response_type/)
        done()
      })
    })
  })
});
