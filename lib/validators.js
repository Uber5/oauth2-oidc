
module.exports = {
  users: {
    validate: user => {
      return Promise.resolve([]) // TODO: do we need validation?
    }
  },
  accessTokens: {
    validate: token => {
      const errors = []
      const requiredProps = [ 'clientId', 'userId', 'authId', 'token', 'type', 'scope' ]
      requiredProps.forEach(requiredProp => {
        if (!token[requiredProp]) {
          errors.push(`Property ${ requiredProp } missing or empty in ${ "accessTokens" } instance.`)
        }
      })
      return Promise.resolve(errors)
    }
  },
  auths: {
    validate: auth => {
      const errors = []
      const requiredProps = [ 'clientId', 'scope', 'userId', 'code', 'redirectUri', 'responseType', 'status' ]
      requiredProps.forEach(requiredProp => {
        if (!auth[requiredProp]) {
          errors.push(`Property ${ requiredProp } missing or empty in ${ "auths" } instance.`)
        }
      })
      return Promise.resolve(errors)
    }
  }
}
