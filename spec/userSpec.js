'use strict'

const debug = require('debug')('oauth2-oidc')

describe('user', function() {
  let config
  beforeEach(function(done) {
    getState().then(state => {
      const oidc = new OAuth2OIDC({ state, login_url: '/xyz' })
      config = oidc.options
      done()
    })
  })
  describe('given a user', function() {
    it('allows me to update the password', function(done) {
      Promise.resolve(buildAndSaveUser(config.state.collections, {
        password: 'secret887',
        passConfirm: 'secret887'
      })).then((u) => {
        debug('user built', u)
        u.password = u.passConfirm = 'changed'
        return config.state.collections.user.save(u)
      }).then((u) => {
        expect(u).toBeTruthy()
        done()
      }).catch((err) => {
        debug('updating password, err', err)
        throw new Error(err)
      })
    })
  })
  describe('finding', function() {
    it('is empty when user not found', done => {
      config.state.collections.user.findOne({ thisQuery: 'should return nothing' })
      .then(user => {
        expect(user).toBeFalsy()
        done()
      })
      .catch(err => {
        console.log('testing for empty', err)
        throw err
      })
    })
  })
})
