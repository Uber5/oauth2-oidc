"use strict";

describe('token', function() {
  describe('extracting client credentials from header', function() {

    let oidc

    beforeEach(function() {
      oidc = new OAuth2OIDC({ state: {}, login_url: '/login', })
    })

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
  })
})
