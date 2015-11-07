var httpMocks = require('node-mocks-http');

describe('auth', function() {

  var OAuth2OIDC = require('../index');
  var oidc = new OAuth2OIDC({});

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

});
