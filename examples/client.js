const TestClient = require('../spec/helpers/testClient')

const client = new TestClient({
  oauth: {
    clientID: 'testclient',
    clientSecret: 'testclient-secret',
    site: 'http://localhost:3001', // TODO: cannot use fixed port
    tokenPath: '/user/token',
    authorizationPath: '/user/authorize'
  },
      authorizationUrl: 'http://localhost:3001/auth'
})

const port = process.env.PORT || 3010

const server = client.app.listen(port, function() {
  console.log('client listening on port ' + server.address().port);
})
