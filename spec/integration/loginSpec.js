const Browser = require('zombie');

describe('Visit client', function() {

  const browser = new Browser();
  var client, config, provider;

  beforeEach(function(done) {

    client = new TestClient();

    testConfig(function(err, cfg) {
      if (err) throw new Error(err);
      config = cfg
      provider = new TestProvider(config);

      // make the provider listen
      const providerServer = provider.app.listen(function() {
        const providerPort = providerServer.address().port
        debug(`providerServer, port=${ providerPort }`)

        // second, make the client listen
        const clientServer = client.app.listen(function() {
          const port = clientServer.address().port
          console.log('client app listening at ' + port)
          client.baseUrl = `http://localhost:${ port }`
          client.initOAuth({
            clientID: 'client1',
            clientSecret: 'secret123',
            site: `http://localhost:${ providerPort }`,
            tokenPath: '/user/token',
            authorizationPath: '/user/authorize'
          })
          const clientHomeUrl = 'http://localhost:' + clientServer.address().port + '/';
          browser.visit(clientHomeUrl, done);
        })
      })
    })
  });

  afterEach(function(done) {
    config.state.connections.default._adapter.teardown(done)
  })

  // to avoid regression of commit 6f923c6
  it('has config with all (more than one) collections', function(done) {
    const collections = config.state.collections;
    [ 'user', 'client' ].forEach((name) => {
      // console.log('config.state.collections', name)
      expect(collections[name]).not.toBe(undefined)
    })
    done()
  })

  it('allows logging in', function(done) {
    browser.clickLink('a', function(err) {
      expect(err).toBe(undefined);
      console.log('browser.text', browser.text())
      console.log('browser.location', browser.location.href)
      browser.assert.text('title', 'Login');
      done();
    })
  });
})
