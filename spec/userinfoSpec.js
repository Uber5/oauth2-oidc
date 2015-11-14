"use strict";

describe('userinfo', function() {
  let oidc

  beforeEach(function() {
    oidc = new OAuth2OIDC({ state: {}, login_url: '/login', })
  })

  describe('having an access token', function() {
    let config, user, access
    beforeEach(function(done) {
      buildTestConfig().then((c) => {
        config = c
        return buildUser()
      }).then((user) => {
        console.log('user', user)
        return config.state.collections.user.create(user)
      }).then((savedUser) => {
        console.log('savedUser', savedUser)
        user = savedUser
        return buildAccess({ user: savedUser })
      }).then((acc) => {
        console.log('acc', acc)
        return config.state.collections.access.create(acc)
      }).then((savedAccess) => {
        console.log('savedAccess', savedAccess)
        access = savedAccess
        done()
      }).catch((err) => {
        console.log('err', err)
        done(err)
      })
    })
    it('provides userinfo', function(done) {
      expect(true).toBe(false) // TODO
      done()
    })
  })

})
