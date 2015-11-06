const Browser = require('zombie');
// const TestClient = require('../helpers/testClient')

describe('Visit client', function() {
  const browser = new Browser();
  var client;
  beforeEach(function(done) {
    client = new TestClient();
    const server = client.app.listen(function() {
      const port = server.address().port
      console.log('client app listening at ' + port)
      client.initOAuth({
        clientID: 'client1',
        clientSecret: 'secret123',
        site: `http://localhost:${ port }`,
        tokenPath: '/user/token',
        authorizationPath: '/user/authorize'
      })
      const clientHomeUrl = 'http://localhost:' + server.address().port + '/';
      browser.visit(clientHomeUrl, done);
    })
  });
  it('allows logging in', function(done) {
    browser.clickLink('a', function(err) {
      expect(err).toBe(undefined);
      browser.assert.text('title', 'Login');
      done();
    })
  });
})
