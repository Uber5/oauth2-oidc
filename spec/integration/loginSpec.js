const Browser = require('zombie');

describe('Visit client', function() {
  const browser = new Browser();
  beforeEach(function(done) {
    const clientHomeUrl = 'http://localhost:3010/';
    // start 
    browser.visit(clientHomeUrl, done);
  });
  it('allows logging in', function(done) {
    browser.clickLink('a', function(err) {
      expect(err).toBe(undefined);
      browser.assert.text('title', 'Login');
      done();
    })
  });
})
