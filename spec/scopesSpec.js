'use strict';

describe('getting scopes', function() {
  const oidc = new OAuth2OIDC({ state: {}, login_url: '/login', })
  const scenario = [
    {
      desc: 'uses given query scope',
      req: { query: { scope: 'a' } },
      expected: [ 'a' ]
    },
    { desc: 'uses given query scope, which is an array',
      req: { query: { scope: 'a b' } },
      expected: [ 'a', 'b' ]
    },
    { desc: 'uses client scope, as query scope empty',
      req: { query: { scope: '' }, client: { scope: [ '123' ] } },
      expected: [ '123' ] },
    { desc: 'uses client scope, as query scope not present',
      req: { query: {}, client: { scope: [ '123' ] } },
      expected: [ '123' ] },
  ]
  scenario.forEach((scenario) => {
    let req
    beforeEach(function() {
      req = scenario.req
    })
    it(scenario.desc, function() {
      expect(oidc._getScopesFromQueryOrClient(req)).toEqual(scenario.expected)
    })
  })
})
