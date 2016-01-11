"use strict";

const schemas = require('./lib/schemas'),
      crypto = require('crypto'),
      debug = require('debug')('oauth2-oidc')

function generateCode(length) {
  length = length || 12
  // TODO: We have (at least one) client who does not properly uri-encode
  // codes, therefore we switch to 'hex' encoded by default. In order to use,
  // as a provider, a more efficient encoding (e.g. the previously used
  // 'base64'), environment variable CODE_ENCODING can be defined.
  return crypto.randomBytes(length).toString(process.env.CODE_ENCODING || 'hex')
}

function uriQuerySeparator(uri) {
  return uri.match(/\?/) ? '&' : '?'
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
        if (err) return res.status(409).send(`client with id ${ query.client_id } not found. err=${ err }`);
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
      const requested_redirect_uri = req.query.redirect_uri
      const permitted = req.client.redirect_uris.reduce((memo, uri) => {
        if (memo) return memo;
        return requested_redirect_uri.match(`^${ uri }`)
      }, false)
      if (permitted) {
        next()
      } else {
        next({ status: 400, error: 'invalid_request', error_description: 'redirect_uri not permitted' })
      }
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

    function createAuth(req, scopes, code, redirect_uri, response_type) {
      return req.state.collections.auth.create({
        client: req.client.id,
        scope: scopes,
        user: req.session.user,
        code: code,
        redirectUri: redirect_uri,
        responseType: response_type,
        status: 'created'
      })
    }

    const byResponseType = {
      code: function(req, res, next) {
        const client = req.client
        const query = req.query
        // TODO: some checks missing (token type, scopes, ...)
        Promise.resolve(generateCode()).then((code) => {
          const scopes = query.scope.length > 0 ? query.scope.split(' ') : client.scope
          return createAuth(req, scopes, code, query.redirect_uri, query.response_type)
        }).then((auth) => {
          debug('_authorize, auth created', auth)
          return res.redirect(req.query.redirect_uri
            + uriQuerySeparator(req.query.redirect_uri) + 'code=' + encodeURIComponent(auth.code)
            + '&state=' + req.query.state)
        }).catch((err) => {
          debug('unable to authorize', err)
          next(err)
        })
      },
      token: (req, res, next) => {
        if (!req.client.implicitFlow) {
          return next({
            status: 401,
            error: 'unauthorized_client',
            error_description: 'The client is not authorized to request an access token using this method'
          })
        }
        const query = req.query
        const scopes = query.scope.length > 0 ? query.scope.split(' ') : client.scope
        Promise.resolve(scopes).then((scopes) => {
          return createAuth(req, scopes, 'implicit', query.redirect_uri, query.response_type)
        }).then((auth) => {
          req.auth = auth
          return this._createAccessToken(req)
        }).then((access) => {
          req.access = access
          return this._createRefreshToken(req)
        }).then((refresh) => {
          const access = req.access
          const data = {
            access_token: access.token,
            token_type: access.type,
            expires_in: this._expiresInSeconds(req.client, access.createdAt),
            refresh_token: refresh.token
          }
          const baseUrl = req.query.redirect_uri
          let redirectUrl = req.query.redirect_uri + uriQuerySeparator(baseUrl)
                      + 'access_token=' + encodeURIComponent(data.access_token)
                      + '&token_type=' + data.token_type
                      + '&expires_in=' + data.expires_in
                      + '&scope=' + scopes
          if (req.query.state) redirectUrl += ('&state=' + req.query.state)
          res.redirect(redirectUrl)
          next()
        }).catch((err) => {
          next(err)
        })
      }
    }

    return function(req, res, next) {
      const query = req.query
      debug('_getClient, req.query', query)
      const response_type = query.response_type
      if (!byResponseType[response_type]) {
        return next({
          status: 400,
          error: 'invalid_request',
          error_description: `Invalid or unsupported response_type "${ response_type }"`
        })
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
      this._verifyRedirectUri(),
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
          return reject({ status: 401, error: 'invalid_request', error_description: 'missing authorization header' })
        }
        const credentials = this._extractCredentialsFromHeaderValue(authHeader)
        if (credentials.error) {
          const msg = 'unable to extract credentials, see https://tools.ietf.org/html/rfc6749#section-2.3: '
            + credentials.error
          return reject({ status: 401, error: 'invalid_request', error_description: msg })
        }
        debug('credentials', credentials)
        resolve(credentials)
      }).catch((err) => {
        debug('_getClientOnTokenRequest, no credentials in header')
        return new Promise((resolve, reject) => {
          if (!req.body.client_id) return reject(err);
          debug('_getClientOnTokenRequest, trying with client_id', { body: req.body })
          req.state.collections.client.findOne({ key: req.body.client_id })
          .then((client) => {
            debug('_getClientOnTokenRequest, client found', client)
            if (!client) {
              return reject({
                status: 404,
                error: 'invalid_request',
                error_description: `client with id ${ req.body.client_id } not found.`
              })
            }
            if (client.enforceAuthOnTokenRequest) {
              return reject(err)
              // return reject({ status: 401, error: 'invalid_request', error_description: 'missing authorization header (2)' })
            } else {
              return resolve({ client_id: client.key, secret: client.secret })
            }
          }).catch((err) => {
            debug('_getClientOnTokenRequest, err loading client via client_id', err)
            reject(err)
          })
        })
      }).then((credentials) => {
        return new Promise((resolve, reject) => {
          req.state.collections.client.findOne({ key: credentials.client_id }, (err, client) => {
            if (err) {
              const msg = `client with id ${ credentials.client_id } not found.`;
              return reject({ status: 404, error: 'invalid_request', error_description: msg })
            }
            if (!client) {
              return reject({
                status: 404,
                error: 'invalid_request',
                error_description: `client with id ${ credentials.client_id } not found.`
              })
            }
            if (client.secret != credentials.secret) {
              const msg = `incorrect secret for client ${ credentials.client_id }`
              return reject({ status: 401, error: 'invalid_request', error_description: msg })
            }
            resolve(client)
          })
        })
      }).then((client) => {
        req.client = client
        next()
      }).catch((err) => {
        debug('err', err.stack)
        // res.status(err.status || 500)
        next(err)
      })
    }
  }

  _consumeClientCode(req) {
    const collections = req.state.collections
    return Promise.resolve().then(() => {
      if (!req.body.code) {
        throw { status: 400, error: 'invalid_request', error_description: '"code" is required' }
      }
      return collections.auth.findOne({
        client: req.client.id,
        code: req.body.code,
        status: 'created'
      })
    }).then((auth) => {
      debug('token endpoint, auth found', auth)
      if (!auth) {
        throw {
          status: 400,
          error: 'invalid_request',
          error_description: `auth for client ${ req.client.key } and code ${ req.body.code } not found.`
        }
      }
      req.auth = auth
      auth.status = 'consumed'
      return auth.save()
    }).then(() => {
      debug('auth saved', req.auth)
      return Promise.resolve()
    })
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
          return next({
            status: 400,
            error: 'missing_parameters',
            error_description: 'sub, redirect_uri and scope are required'
          })
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
          debug('magickey, auth', auth)
          res.status(201).send({ key: auth.magicKey })
          next()
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
          return next({ status: 400, error: 'missing_parameters', error_description: 'key is required'})
        }
        Promise.resolve(req.state.collections.auth.findOne({ magicKey: key, status: 'created' }))
        .then((auth) => {
          if (!auth) {
            throw { status: 401, error: 'key_invalid', error_description: 'key not found or expired' }
          }
          req.auth = auth
          auth.status = 'consumed'
          return auth.save()
        }).then(() => {
          debug('magicopen, saved', arguments)
          next()
        }).catch((err) => {
          debug('magicopen, err', err)
          return next(err)
        })
      },
      (req, res, next) => { // check expiry
        const auth = req.auth
        const client = req.auth.client // TODO: may have to query
        if (this._expiresInSeconds(client, auth.createdAt) < 0) {
          return next({ status: 401, error: 'key_invalid', error_description: 'key not found or expired' })
        }
        next()
      },
      (req, res, next) => {
        Promise.resolve(req.state.collections.user.findOne({ id: req.auth.user })).then((user) => {
          req.session && (req.session.user = user) // keep user in session (if there is a session)
          debug('magicopen, user', user)
          next()
        }).catch((err) => {
          debug('magicopen, resolving user, err', err)
          next(err)
        })
      },
      (req, res, next) => { // respond
        const auth = req.auth
        debug('magicopen, redirect', auth)
        res.redirect(auth.redirectUri
          + uriQuerySeparator(auth.redirectUri) + 'code=' + encodeURIComponent(auth.code))
        next()
      }
    ]
  }

  _createAccessToken(req) {
    const collections = req.state.collections
    const auth = req.auth
    debug('_createAccessToken, auth', auth)
    return collections.access.create({
      token: generateCode(48),
      type: 'bearer',
      scope: auth.scope,
      client: req.client,
      user: auth.user,
      auth: auth
    })
  }

  _createRefreshToken(req) {
    const collections = req.state.collections
    const auth = req.auth
    return collections.refresh.create({
      token: generateCode(42),
      scope: auth.scope,
      auth: auth,
      status: 'created'
    })
  }

  _invalidateRefreshToken(req) {
    const collections = req.state.collections
    if (!req.body.refresh_token) {
      return Promise.reject({ status: 400, error: 'invalid_request', error_description: 'no refresh token given' })
    }
    return Promise.resolve(req.body.refresh_token).then((id) => {
      debug('refresh token id', id)
      return collections.refresh.findOne({ token: id, status: 'created' })
    }).then((token) => {
      if (!token) {
        return Promise.reject({
          status: 401,
          error: 'invalid_token',
          error_description: 'refresh token not found or expired'
        })
      }
      req.token = token
      return collections.auth.findOne({ id: token.auth })
    }).then((auth) => {
      req.auth = auth
      const token = req.token
      const client = req.client
      debug('_invalidateRefreshToken, client and token and auth', req.client, token, auth)
      if (auth.client != client.id) {
        return Promise.reject({
          status: 400,
          error: 'invalid_request',
          error_description: 'refresh token does not belong to client' })
      }
      token.status = 'consumed'
      return token.save()
    })
  }

  token() {
    return [
      (req, res, next) => { // validation
        if (!req.body.grant_type) {
          return next({ status: 400, error: 'invalid_request', error_description: 'grant_type required' })
        }
        next()
      },
      this._useState(),
      this._getClientOnTokenRequest(),
      (req, res, next) => {
        if (req.body.grant_type == 'authorization_code') {
          this._consumeClientCode(req).then(() => {
            return this._createAccessToken(req)
          }).then((access) => {
            req.access = access
            return this._createRefreshToken(req)
          }).then((refresh) => {
            const access = req.access
            res.send({
              access_token: access.token,
              token_type: access.type,
              expires_in: this._expiresInSeconds(req.client, access.createdAt),
              refresh_token: refresh.token
            })
          }).catch((err) => {
            next(err)
          })
        } else if (req.body.grant_type == 'refresh_token') {
          this._invalidateRefreshToken(req).then(() => {
            return this._createAccessToken(req)
          }).then((access) => {
            req.access = access
            return this._createRefreshToken(req)
          }).then((refresh) => {
            const access = req.access
            res.send({
              access_token: access.token,
              token_type: access.type,
              expires_in: this._expiresInSeconds(req.client, access.createdAt),
              refresh_token: refresh.token
            })
            next()
          }).catch((err) => {
            debug('err', err.stack)
            next(err)
          })
        }
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
          throw ({ status: 401, error: 'invalid_token', message: 'access token not found or expired' });
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
        return next({
          status: 400,
          error: 'invalid_request',
          error_description: 'no client scope present'
        })
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
        return next({ status: 400, error_description: 'no token scope present' })
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
        next({ status: 401, error: 'expired', error_description: 'token provided has expired.' })
      }
    }
  }

  _sendUserInfo(req, res, next) {
    const data = {
      sub: req.user.sub,
      email: req.user.sub, // TODO: needs to be adjustable / customizable
      name: '(no name set)', // TODO: add more properties of the user to the response
      preferred_username: '(no preferred name set)'
    }
    res.send(data)
    next()
  }

  _removeAccessAndAuth(req, res, next) {

    debug('_removeAccessAndAuth, user', req.user)
    const collections = req.state.collections
    const user = req.user

    Promise.resolve().then(() => {
      return collections.auth.destroy({ user: user.id })
    }).then((r) => {
      debug(`_removeAccessAndAuth, destroyed auths for user ${ user.id }`, r)
      return collections.access.destroy({ user: user.id })
    }).then((r) => {
      debug(`_removeAccessAndAuth, destroyed access for user ${ user.id }`, r)
      next()
    }).catch((err) => {
      debug(`_removeAccessAndAuth, unable to remove tokens for ${ user.id }`, err)
      return next({
        status: 500,
        error: 'internal',
        error_description: `unable to destroy tokens for user ${ user.id }`
      });
    })

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

  logout() {
    return [
      this._useState(),
      this._getAccessTokenAndUserOnRequest(),
      this._ensureNotExpired(),
      this._removeAccessAndAuth
    ]
  }
}

module.exports = OAuth2OIDC;
module.exports.state = {
  defaultSpecifications: require('./lib/specifications')
}
