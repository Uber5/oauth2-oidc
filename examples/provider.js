"use strict";

const OAuth2OIDC = require('../'),
      TestProvider = require('../spec/helpers/testProvider'),
      state = require('./state'),
      bcrypt = require('bcryptjs')

const port = process.env.PORT || 3001

const specs = OAuth2OIDC.state.defaultSpecifications
let replContext, provider, server, adapter, connection

// determine adapter
if (process.env.MONGO_URL) {
  adapter = require('sails-mongo')
  connection = { adapter: 'adapter1', url: process.env.MONGO_URL }
} else {
  adapter = require('sails-memory')
  connection = null
}

state.getDefaultStateConfig(specs, adapter, connection, function(err, ontology) {
  if (err) throw new Error(err);
  provider = new TestProvider({
    state: ontology,
    login_url: '/login'
  })
  if (replContext) {
    replContext.provider = provider
    replContext.ontology = ontology
  }

  // (re)create sample data
  const User = ontology.collections.user, Client = ontology.collections.client
  User.destroy({ sub: 'chris1@test.com' }).then(() => {
    return Client.destroy({ key: 'testclient' })
  }).then(() => {
    // sample user
    return ontology.collections.user.create({
      sub: 'chris1@test.com',
      password: '123',
      passConfirm: '123',
    })
  }).then(() => {
    // sample client
    return ontology.collections.client.create({
      key: 'testclient',
      secret: 'very secret should it be',
      name: 'some test client',
      redirect_uris: [ 'http://localhost:3010' ],
      scope: [ 'openid', 'magiclink' ]
    })
  }).then(function() {
    // ... and listen
    server = provider.app.listen(port, function() {
      console.log('provider listening on port ' + port)
      if (replContext) {
        replContext.server = server
      }
    })
  }).catch((err) => {
    console.log('err', err)
  })

})

if (process.env.WITH_REPL) {
  const repl = require('repl')
  const s = repl.start('> ')
  replContext = s.context
}
