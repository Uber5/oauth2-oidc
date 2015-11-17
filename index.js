"use strict";

const schemas = require('./lib/schemas'),
      crypto = require('crypto'),
      debug = require('debug')('oauth2-oidc')

function generateCode(length) {
  length = length || 12
  return crypto.randomBytes(length).toString('base64')
}

class OAuth2OIDC {

  constructor(options) {
    this.options = options || {}
    const errorMessage = schemas.validationErrors(this.options, schemas.configSchema);
    if (errorMessage) throw new Error('invalid options: ' + errorMessage);
  }

  _validateAuth(req, res, next) {
    var errors = schemas.validate(req.query, schemas.authSchema).errors;
    if (!errors.length) {
      return next();
    } else {
      return next(schemas.displayableValidationErrors(errors));
    }
  }

  _getClient() {
    const options = this.options
    return function(req, res, next) {
      const query = req.query
      req.state.collections.client.findOne({ key: query.client_id }, (err, client) => {
        if (err) return res.status(409).send(`client with id ${ query.client_id } not found.`);
        if (!client) {
          return res.status(404).send(`client with id ${ query.client_id } not found.`)
        } else {
          req.client = client
          next()
        }
      })
    }
  }

  _verifyRedirectUri() {
    return function(req, res, next) {
      next('huh? probably not needed')
    }
  }

  _redirectToLoginUnlessLoggedIn() {
    return (req, res, next) => {
      if (req.session && req.session.user) {
        return next()
      } else {
        req.session.return_url = req.url
        debug('_redirectToLoginUnlessLoggedIn, return_url=' + req.session.return_url)
        return res.redirect(this.options.login_url)
      }
    }
  }

  _authorize() {
    const options = this.options

    const byResponseType = {
      code: function(req, res, next) {
        const client = req.client
        const query = req.query
        // TODO: some checks missing (token type, scopes, ...)
        new Promise((resolve, reject) => {
          resolve(generateCode())
        }).then((code) => {
          return req.state.collections.auth.create({
            client: req.client.id,
            scope: query.scope.split(' '),
            user: req.session.user,
            code: code,
            redirectUri: query.redirect_uri,
            responseType: query.response_type,
            status: 'created' // TODO: really needed?
          })
        }).then((auth) => {
          debug('_authorize, auth created', auth)
          return res.redirect(req.query.redirect_uri
            + '?code=' + encodeURIComponent(auth.code)
            + '&state=' + req.query.state)
        }).catch((err) => {
          debug('unable to authorize', err)
          next(err)
        })
      }
    }

    return function(req, res, next) {
      const query = req.query
      debug('_getClient, req.query', query)
      const response_type = query.response_type
      if (!byResponseType[response_type]) {
        return next(`Invalid or unsupported response_type ${ response_type }`)
      } else {
        return byResponseType[response_type](req, res, next)
      }
    }

  }

  _useState() {
    return (req, res, next) => {
      req.state = this.options.state
      next()
    }
  }

  auth() {
    return [
      this._validateAuth,
      this._useState(),
      this._getClient(),
      this._redirectToLoginUnlessLoggedIn(),
      this._authorize()
    ];
  }

  _extractCredentialsFromHeaderValue(value) {
    const match = value.match(/^Basic (.+)$/)
    if (!match || match.length != 2 || !match[1]) return { error: 'expected "Basic" authorization header.' };
    const decoded = new Buffer(match[1], 'base64').toString('utf-8')
    const splitted = decoded.split(':')
    if (splitted.length != 2) return { error: 'unable to extract credentials from Basic authorization header.'};
    return { client_id: splitted[0], secret: splitted[1] }
  }

  _getClientOnTokenRequest() {
    return (req, res, next) => {
      new Promise((resolve, reject) => {
        const authHeader = req.get('authorization')
        if (!authHeader) {
          return reject({ status: 401, message: 'missing authorization header' })
        }
        const credentials = this._extractCredentialsFromHeaderValue(authHeader)
        if (credentials.error) {
          const msg = 'unable to extract credentials, see https://tools.ietf.org/html/rfc6749#section-2.3: '
            + credentials.error
          return reject({ status: 401, message: msg })
        }
        debug('credentials', credentials)
        resolve(credentials)
      }).then((credentials) => {
        return new Promise((resolve, reject) => {
          req.state.collections.client.findOne({ key: credentials.client_id }, (err, client) => {
            if (err) {
              const msg = `client with id ${ query.client_id } not found.`;
              return reject({ status: 409, message: msg })
            }
            if (!client) {
              return reject({ status: 404, message: `client with id ${ query.client_id } not found.` })
            }
            if (client.secret != credentials.secret) {
              const msg = `incorrect secret for client ${ credentials.client_id }`
              return reject({ status: 401, message: msg })
            }
            resolve(client)
          })
        })
      }).then((client) => {
        req.client = client
        next()
      }).catch((err) => {
        debug('err', err)
        // TODO: must follow spec?
        res.status(err.status)
        res.send({ error_description: err.message })
        next()
      })
    }
  }

  _consumeClientCode() {
    return (req, res, next) => {
      const collections = req.state.collections
      collections.auth.findOne({
        client: req.client.id,
        code: req.body.code,
        status: 'created'
      }).then((auth) => {
        debug('token endpoint, auth found', auth)
        if (!auth) throw new Error(`auth for client ${ req.client.id } and code ${ req.body.code } not found.`)
        req.auth = auth
        auth.status = 'consumed'
        return auth.save()
      }).then(() => {
        debug('auth saved', req.auth)
        next()
      }).catch((err) => {
        return next(`no token found for code ${ req.body.code }: ${ err }`)
      })
    }
  }

  token() {
    return [
      this._useState(),
      this._getClientOnTokenRequest(),
      this._consumeClientCode(),
      (req, res, next) => {
        const collections = req.state.collections
        const auth = req.auth
        collections.access.create({
          token: generateCode(48),
          type: 'bearer',
          scope: auth.scope,
          client: req.client,
          user: auth.user,
          auth: auth
        }).then((access) => {
          res.send({
            access_token: access.token,
            token_type: access.type,
            expires_in: 3600, // TODO: implement properly
            refresh_token: 'xxx', // TODO: dummy
          })
        }).catch((err) => {
          next(err)
        })
      }
    ]
  }

  _getAccessToken(value) {
    if (!value) return null;
    const match = value.match(/^Bearer (.+)$/)
    if (!match || match.length != 2 || !match[1]) return undefined;
    return match[1]
  }

  _getAccessTokenAndUserOnRequest() {
    return (req, res, next) => {
      debug('req.headers', req.headers)
      const token = this._getAccessToken(req.get('authorization'))
      if (!token) return next({ status: 401, message: 'missing or invalid bearer token' });
      debug('bearer token', token)
      const collections = req.state.collections
      Promise.resolve(collections.access.findOne({ token: token }))
      .then((token) => {
        if (!token) {
          debug('access token not found', token)
          throw ({ status: 401, message: 'access token not found or expired' });
        }
        req.token = token
        debug('token found', token)
        return collections.user.findOne({ id: token.user })
      }).then((user) => {
        if (!user) {
          debug('user of token not found', req.token)
          throw ({ status: 401, message: 'user of token not found'});
        }
        req.user = user
        next()
      }).catch((err) => {
        debug('err while getting access token and user', err)
        next(err)
      })
    }
  }

  _hasScopes() {
    const requiredScopes = Array.prototype.slice.call(arguments)
    const isScopeGivenIn = (givenScopes, requested) => {
      return givenScopes.reduce((memo, scope) => {
        if (memo) return memo;
        return scope.match(requested)
      }, false)
    }
    return (req, res, next) => {
      let err
      requiredScopes.forEach(function(scope) {
        if (!err && !isScopeGivenIn(req.token.scope, scope)) {
          err = `scope ${ scope } required but not present in ${ req.token.scope }`
        }
      })
      next(err)
    }
  }

  _sendUserInfo(req, res, next) {
    const data = {
      sub: req.user.sub,
      name: 'dummy' // TODO: add more properties of the user to the response
    }
    res.send(data)
    next()
  }

  userinfo() {
    return [
      this._useState(),
      this._getAccessTokenAndUserOnRequest(),
      this._hasScopes('openid', /profile|email/),
      this._sendUserInfo
    ]
  }

}

module.exports = OAuth2OIDC;
module.exports.state = {
  defaultSpecifications: require('./lib/specifications')
}
