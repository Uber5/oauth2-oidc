const request = require('request')

function basicAuthorizationValueForClient(clientId, clientSecret) {
  return new Buffer(`${ clientId }:${ clientSecret }`).toString('base64')
}

exports.createMagicLink = function(config, redirect_uri, sub, callback) {
  if (!redirect_uri || !sub) return callback('invalid parameters');
  request({
    method: 'POST',
    url: config.site + '/magickey',
    headers: {
      authorization: `Basic ${ basicAuthorizationValueForClient(config.clientID, config.clientSecret) }`,
      accept: 'application/json'
    },
    json: true,
    body: {
      sub: sub,
      redirect_uri: redirect_uri,
      scope: 'openid profile'
    }
  }, (err, response, body) => {
    if (!err && response.statusCode != 201) {
      err = body
      body = null
    }
    callback(err, body)
  })
}
