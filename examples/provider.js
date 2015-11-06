const TestProvider = require('../spec/helpers/testProvider')

const provider = new TestProvider()
const port = process.env.PORT || 3001

const server = provider.app.listen(port, function() {
  console.log('provider listening on port ' + port)
})
