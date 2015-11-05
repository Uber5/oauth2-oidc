var httpMocks = require('node-mocks-http');

describe('auth', function() {

  var OAuth2OIDC = require('../index');
  var oidc = new OAuth2OIDC({});

  it('succeeds if query param x1 given (DUMMY)', function(done) {
    var req = httpMocks.createRequest({
      method: 'GET',
        url: '/whatever',
        params: {
          x1: 3
        }
    });
    var res = httpMocks.createResponse();
    oidc._validateAuth(req, res, function(err) {
      expect(err).toBe(undefined);
      done();
    });
  });
  it('fails if no param given', function(done) {
    var req = httpMocks.createRequest({
      method: 'GET',
        url: '/whatever',
        params: {
          x2: 3
        }
    });
    var res = httpMocks.createResponse();
    oidc._validateAuth(req, res, function(err) {
      expect(err).toEqual('expected x1 param');
      done();
    });
  });
});
