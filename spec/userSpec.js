'use strict'

describe('user', function() {
  describe('given a user', function() {
    let config
    beforeEach(function(done) {
      testConfig(function(err, cfg) {
        config = cfg
        done()
      })
    })
    afterEach(function(done) {
      config.state.connections.default._adapter.teardown(done)
    })
    it('allows me to update the password', function(done) {
      Promise.resolve(buildAndSaveUser(config.state.collections)).then((u) => {
        console.log('user built', u)
        u.password = u.passConfirm = 'changed'
        return u.save()
      }).then((u) => {
        expect(u).toBeTruthy()
        console.log(u)
        done()
      }).catch((err) => {
        console.log('err', err)
        throw new Error(err)
      })
    })
  })
})
