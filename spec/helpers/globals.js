global.debug = require('debug')('oauth2-oidc')
global.testConfig = {
  state: {
    client: {
      findOne: function(query, cb) {
        process.nextTick(() => {
          cb(null, { id: 123, secret: 'dummy' })
        })
      }
    }
  }
}
