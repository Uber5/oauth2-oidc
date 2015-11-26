"use strict";

const OAuth2OIDC = require('../'),
      TestProvider = require('../spec/helpers/testProvider'),
      state = require('./state'),
      sailsMemoryAdapter = require('sails-memory'),
      bcrypt = require('bcryptjs')

const port = process.env.PORT || 3001

const specs = OAuth2OIDC.state.defaultSpecifications
const adapter = sailsMemoryAdapter
let replContext, provider, server

state.getDefaultStateConfig(specs, adapter, function(err, ontology) {
  if (err) throw new Error(err);
  provider = new TestProvider({
    state: ontology,
    login_url: '/login'
  })
  if (replContext) {
    replContext.provider = provider
    replContext.ontology = ontology
  }

  ontology.collections.user.create({
    sub: 'chris1@test.com',
    password: '123',
    passConfirm: '123',
  }).catch((err) => {
    console.log('err', err)
  })

  // inject testclient
  ontology.collections.client.create({
    key: 'testclient',
    secret: 'very secret should it be',
    name: 'some test client',
    redirect_uris: [ 'http://localhost:3010' ],
    scope: [ 'openid', 'magiclink' ]
  }).then(function() {
    // TODO: refactor to create user in promise (before listening)
  }).then(function() {
    // ... and listen
    server = provider.app.listen(port, function() {
      console.log('provider listening on port ' + port)
      if (replContext) {
        replContext.server = server
      }
    })
  }).catch(function(err) {
    console.log(err)
  })

})

if (process.env.WITH_REPL) {
  const repl = require('repl')
  const s = repl.start('> ')
  replContext = s.context
}
