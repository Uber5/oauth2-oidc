const OAuth2OIDC = require('../'),
      TestProvider = require('../spec/helpers/testProvider'),
      state = require('./state'),
      sailsMemoryAdapter = require('sails-memory'),
      bcrypt = require('bcryptjs')

const port = process.env.PORT || 3001

const specs = OAuth2OIDC.state.defaultSpecifications
const adapter = sailsMemoryAdapter
state.getDefaultStateConfig(specs, adapter, function(err, ontology) {
  if (err) throw new Error(err);
  const provider = new TestProvider({
    state: ontology,
    login_url: '/login'
  })

  ontology.collections.user.create({
    sub: 'chris1',
    password: 'secret!',
    passConfirm: 'secret!',
  }).catch((err) => {
    console.log('err', err)
  })

  // inject testclient
  ontology.collections.client.create({
    key: 'testclient',
    secret: 'very secret should it be',
    name: 'some test client',
    redirect_uris: [ 'http://localhost:3010' ]
  }).then(function() {
    // TODO: refactor to create user in promise (before listening)
  }).then(function() {
    // ... and listen
    const server = provider.app.listen(port, function() {
      console.log('provider listening on port ' + port)
    })
  }).catch(function(err) {
    console.log(err)
  })

})

