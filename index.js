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
        Promise.resolve(generateCode()).then((code) => {
          return req.state.collections.auth.create({
            client: req.client.id,
            scope: query.scope.split(' '),
            user: req.session.user,
            code: code,
            redirectUri: query.redirect_uri,
            responseType: query.response_type,
            status: 'created'
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

  _expiresInSeconds(client, tokenCreatedAt) {
    const maxLifeInSeconds = 3600 // TODO: configurable in client?
    const lifeInSeconds = (new Date().getTime() - tokenCreatedAt.getTime()) / 1000
    const result = Math.floor(maxLifeInSeconds - lifeInSeconds)
    debug('_expiresInSeconds', new Date().getTime(), tokenCreatedAt.getTime(), lifeInSeconds, result)
    return result
  }

  magickey() {
    return [
      this._useState(),
      this._getClientOnTokenRequest(),
      this._clientHasScopes('magiclink'),
      // TODO: also check if requested scopes are valid for this client
      function(req, res, next) {
        const sub = req.body.sub,
              redirect_uri = req.body.redirect_uri,
              scope = req.body.scope
        let user = null
        debug('magickey, body', req.body)
        debug('magickey, sub', req.param('sub'))
        if (!sub || !redirect_uri || !scope) {
          return next({ error: 'missing_parameters', error_description: 'sub, redirect_uri and scope are required'})
        }
        Promise.resolve(req.state.collections.user.findOne({ sub: sub })).then((foundUser) => {
          debug('foundUser', foundUser)
          if (!foundUser) {
            debug('user not found: ' + sub)
            throw { status: 400, error: 'invalid_user', error_description: 'user not found' }
          }
          user = foundUser
          return user
        }).then((user2) => {
          debug('user2', user2)
          const code = generateCode()
          return req.state.collections.auth.create({
            client: req.client.id,
            scope: scope.split(' '),
            user: user,
            code: code,
            redirectUri: redirect_uri,
            responseType: 'code',
            status: 'created',
            magicKey: generateCode(48)
          })
        }).then((auth) => {
          res.status(201).send({ key: auth.magicKey })
        }).catch((err) => {
          debug('magickey error', err)
          res.status(err.status || 500).send(err)
        })
      }
    ]
  }

  magicopen() {
    return [
      this._useState(),
      (req, res, next) => { // get auth via key
        const key = req.query.key
        debug('magicopen, key', key)
        if (!key) {
          return next({ error: 'missing_parameters', error_description: 'key is required'})
        }
        Promise.resolve(req.state.collections.auth.findOne({ magicKey: key }))
        .then((auth) => {
          if (!auth) {
            return next({ error: 'key_invalid', error_description: 'key not found or expired' })
          }
          req.auth = auth
          next()
        })
      },
      (req, res, next) => { // check expiry
        const auth = req.auth
        const client = req.auth.client // TODO: may have to query
        if (this._expiresInSeconds(client, auth.createdAt) < 0) {
          return next({ error: 'key_invalid', error_description: 'key not found or expired' })
        }
        next()
      },
      (req, res, next) => { // respond
        const auth = req.auth
        debug('magicopen, redirect', auth)
        return res.redirect(auth.redirectUri
          + '?code=' + encodeURIComponent(auth.code)
          + '&state=' + 'magic') // TODO: what about state? would have to come from client, and client would have to check??
      }
    ]
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
            expires_in: this._expiresInSeconds(req.client, access.createdAt),
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

  _isScopeGivenIn(givenScopes, requested) {
    return givenScopes.reduce((memo, scope) => {
      if (memo) return memo;
      return scope.match(requested)
    }, false)
  }

  _hasScopes(presentScopes, requiredScopes, callback) {
    let err
    requiredScopes.forEach((scope) => {
      if (!err && !this._isScopeGivenIn(presentScopes, scope)) {
        err = `scope ${ scope } required but not present in ${ presentScopes }`
      }
    })
    callback(err)
  }

  _clientHasScopes() {
    const requiredScopes = Array.prototype.slice.call(arguments)
    return (req, res, next) => {
      if (!req.client || !req.client.scope) {
        return next('no client scope present')
      }
      this._hasScopes(req.client.scope, requiredScopes, (err) => {
        return next(err)
      })
    }
  }

  _tokenHasScopes() {
    const requiredScopes = Array.prototype.slice.call(arguments)
    return (req, res, next) => {
      if (!req.token || !req.token.scope) {
        return next('no token scope present')
      }
      this._hasScopes(req.token.scope, requiredScopes, (err) => {
        next(err)
      })
    }
  }

  _ensureNotExpired() {
    return (req, res, next) => {
      if (this._expiresInSeconds(req.client, req.token.createdAt) > 0) {
        return next()
      } else {
        next({ error: 'expired', error_description: 'token provided has expired.' })
      }
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
      this._tokenHasScopes('openid', /profile|email/),
      this._ensureNotExpired(),
      this._sendUserInfo
    ]
  }

}

module.exports = OAuth2OIDC;
module.exports.state = {
  defaultSpecifications: require('./lib/specifications')
}
