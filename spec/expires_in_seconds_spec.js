"use strict";

describe('expiry in seconds', function() {

  let oidc, clock, now

  beforeEach(function() {
    oidc = new OAuth2OIDC({ state: {}, login_url: '/login', })
    jasmine.clock().install()
    now = new Date(Date.now())
    jasmine.clock().mockDate(now)
  })

  afterEach(function() {
    jasmine.clock().uninstall()
  })

  it('defaults to 3600 seconds', function() {
    const expires_in = oidc._expiresInSeconds({}, now)
    expect(expires_in).toEqual(3600)
  })
  it('is configurable in the client', function() {
    const ttl = 129
    const expires_in = oidc._expiresInSeconds({ tokenTtlInSeconds: ttl }, now)
    expect(expires_in).toEqual(ttl)
  })
  it('is down to 3599 after 1 tick', function() {
    jasmine.clock().tick(1)
    const expires_in = oidc._expiresInSeconds({}, now)
    expect(expires_in).toEqual(3599)
  })
  it('is down to 1 after 1 hour minus 1 second', function() {
    jasmine.clock().tick(1000 * 60 * 60 - 1000)
    const expires_in = oidc._expiresInSeconds({}, now)
    expect(expires_in).toEqual(1)
  })
  it('is down to 0 after 1 hour', function() {
    jasmine.clock().tick(1000 * 60 * 60)
    const expires_in = oidc._expiresInSeconds({}, now)
    expect(expires_in).toEqual(0)
  })
  it('is down to -3600 after 2 hours', function() {
    jasmine.clock().tick(1000 * 60 * 60 * 2)
    const expires_in = oidc._expiresInSeconds({}, now)
    expect(expires_in).toEqual(-3600)
  })
})
