"use strict";

const OAuth2OIDC = require('../'),
      bcrypt = require('bcryptjs'),
      Provider = require('../spec/helpers/testProvider')

let replContext

exports.setupSampleDataAndStartProvider = function(state, done) {

  // (re)create sample data
  const User = state.user, Client = state.client
  User.destroy({ sub: 'chris1@test.com' })
  .then(() => Client.destroy({ key: 'testclient' }))
  .then(() => state.user.validateAndCreate({
    sub: 'chris1@test.com',
    password: '123',
    passConfirm: '123',
  })).then(() => {
    // sample client
    return state.client.create({
      key: 'testclient',
      secret: 'very secret should it be',
      name: 'some test client',
      redirect_uris: [ 'http://localhost:3010' ],
      scope: [ 'openid', 'magiclink' ]
    })
  }).then(function() {
    // ... and listen
    const port = process.env.PORT || 3001
    const config = { state }
    const server = new Provider(config).app.listen(port, function() {
      console.log('provider listening on port ' + port)
      if (replContext) {
        replContext.server = server
      }
    })
  }).catch((err) => {
    console.log('setupSampleDataAndStartProvider, err', err)
  })

}

if (process.env.WITH_REPL) {
  const repl = require('repl')
  const s = repl.start('> ')
  replContext = s.context
}
