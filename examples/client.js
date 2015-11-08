const TestClient = require('../spec/helpers/testClient')

const config = {
  oauth2: {
    clientID: 'testclient',
    clientSecret: 'testclient-secret',
    site: 'http://localhost:3001', // TODO: cannot use fixed port
    tokenPath: '/user/token',
    authorizationPath: '/user/authorize'
  },
  authorizationUrl: 'http://localhost:3001/auth'
}

const client = new TestClient({})

const port = process.env.PORT || 3010

const server = client.app.listen(port, function() {
  const port = server.address().port
  console.log('client listening on port ' + port)
  client.baseUrl = `http://localhost:${ port }/`
  client.initOAuth(config.oauth2)
})