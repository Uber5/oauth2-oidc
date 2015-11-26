"use strict";

const Browser = require('zombie');

describe('Visit client', function() {

  const browser = new Browser();
  var client, config, provider, username, clientPort;
  let oauthClientConfig

  beforeEach(function(done) {

    client = new TestClient();
    username = nextUsername()

    testConfig(function(err, cfg) {
      if (err) throw new Error(err);
      config = cfg
      provider = new TestProvider(config);

      // make the provider listen
      const providerServer = provider.app.listen(function() {
        const providerPort = providerServer.address().port
        debug(`providerServer, port=${ providerPort }`)

        // define client config
        oauthClientConfig = {
          clientID: 'client1',
          clientSecret: 'secret123',
          site: `http://localhost:${ providerPort }`,
          tokenPath: '/token',
          authorizationPath: '/authorize'
        }

        // make the client listen
        const clientServer = client.app.listen(function() {
          clientPort = clientServer.address().port
          debug('client app listening at ' + clientPort)
          client.baseUrl = `http://localhost:${ clientPort }`
          client.initOAuth(oauthClientConfig)
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
      // debug('config.state.collections', name)
      expect(collections[name]).not.toBe(undefined)
    })
    done()
  })

  it('rejects non-existing client', function(done) {
    browser.clickLink('a', function(err) {
      // expect(err).toBe(undefined)
      expect(browser.text()).toMatch(/client/)
      expect(browser.text()).toMatch(/not found/)
      done()
    })
  })

  describe('when client1 exists', function() {

    beforeEach(function(done) {
      config.state.collections.client.create({
        // id: oauthClientConfig.clientID,
        key: oauthClientConfig.clientID,
        secret: oauthClientConfig.clientSecret,
        name: "Some client",
        redirect_uris: [
          `http://localhost:${ clientPort }`
        ],
        scope: [ 'openid' ]
      }).then(function(client) {
        const u = config.state.collections.user.create({
          sub: username,
          password: 'so-secret',
          passConfirm: 'so-secret',
        })
        return u
      }).then(function(user) {
        done()
      }).catch((err) => {
        debug('ERR', err)
        throw new Error(err)
      })
    })

    it('allows logging in', function(done) {
      browser.clickLink('a', function(err) {
        expect(err).toBe(undefined)
        debug('browser.text', browser.text())
        debug('browser.location', browser.location.href)
        browser.assert.text('title', 'Login')
        browser.fill('username', username)
        .fill('password', 'so-secret')
        .pressButton('Login', function() {
          browser.assert.text('p', 'Logged in as ' + username) // TODO: this should be back on the TestClient
          done();
        })
      })
    });

  })

})
