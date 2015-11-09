const OAuth2OIDC = require('../'),
      TestProvider = require('../spec/helpers/testProvider'),
      state = require('./state'),
      sailsMemoryAdapter = require('sails-memory')

const port = process.env.PORT || 3001

const specs = OAuth2OIDC.state.defaultSpecifications
const adapter = sailsMemoryAdapter
state.getDefaultStateConfig(specs, adapter, function(err, ontology) {
  if (err) throw new Error(err);
  const provider = new TestProvider({
    state: ontology,
    login_url: '/login'
  })

  // inject testclient
  ontology.collections.client.create({
    key: 'testclient',
    secret: 'very secret should it be',
    name: 'some test client',
    redirect_uris: [ 'http://localhost:3010' ]
  }).then(function(client) {
    // ... and listen
    const server = provider.app.listen(port, function() {
      console.log('provider listening on port ' + port)
    })
  })

})

