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
          console.log('AUTH', auth)
          return res.redirect(req.query.redirect_uri
            + '?code=' + encodeURIComponent(auth.code)
            + '&state=' + req.query.state)
        }).catch((err) => {
          console.log('ERR', err)
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

  /** returns array with two elements, which should contain client and client
   * secret */
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

  token() {
    return [
      this._useState(),
      this._getClientOnTokenRequest(),
      (req, res, next) => {
        res.send('not implemented')
      }
    ]
  }
}

module.exports = OAuth2OIDC;
module.exports.state = {
  defaultSpecifications: require('./lib/specifications')
}
