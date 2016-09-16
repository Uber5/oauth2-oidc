
function presenceCheck(type, requiredProps) {
  return function(object) {
    const errors = []
    requiredProps.forEach(requiredProp => {
      if (!object[requiredProp]) {
        errors.push(`Property ${ requiredProp } missing or empty in ${ type }.`)
      }
    })
    return Promise.resolve(errors)
  }
}

module.exports = {
  users: {
    validate: user => {
      return Promise.resolve([]) // TODO: do we need validation?
    }
  },
  accessTokens: {
    validate: presenceCheck('accessTokens', [ 'clientId', 'userId', 'authId', 'token', 'type', 'scope' ])
  },
  auths: {
    validate: presenceCheck('auths', [ 'clientId', 'scope', 'userId', 'code', 'redirectUri', 'responseType', 'status' ])
  },
  clients: {
    validate: presenceCheck('clients', [ 'key', 'secret', 'name', 'redirect_uris', 'scope' ])
  }
}
