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
        return buildAccess({ user: savedUser.id })
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
    afterEach(function(done) {
      config.state.connections.default._adapter.teardown(done)
    })
    it('retrieves access token and user info', function(done) {
      const req = createRequest({
        headers: {
          authorization: `Bearer ${ access.token }`
        }
      }), res = createResponse()
      req.state = config.state
      oidc._getAccessTokenAndUserOnRequest()(req, res, (err) => {
        expect(JSON.stringify(err)).toBe(undefined)
        // expect(res.token).toEqual(access)
        // expect(res.user).toEqual(user)
        done()
      })
    })
    it('provides userinfo', function(done) {
      /** TODO: this is how we *could* test a full req/res cycle without
       * actually listening: */
      /*
      const app = express(),
            request = createRequest(),
            response = createResponse()
      app.all(oidc.userinfo())
      app.handle(request, response, function(err) {
        expect(true).toBe(false) // TODO
        done()
      })
      */
      const req = createRequest()
      req.user = user
      const res = createResponse()
      oidc._sendUserInfo(req, res, function(err) {
        expect(err).toBe(undefined)
        const data = res._getData()
        console.log('data', data)
        expect(data.sub).toEqual(user.sub)
        expect(data.name).toEqual('dummy')
        done()
      })
    })
  })

})
