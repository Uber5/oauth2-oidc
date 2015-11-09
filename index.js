"use strict";

const schemas = require('./lib/schemas')

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

  _performAuth(req, res, next) {
    console.log('do it')
    for (let n in req.state.collections) {
      console.log('req.state.collections', n)
    }
    var query = req.query
    req.state.collections.client.findOne({ key: query.client_id }, function(err, client) {
      if (err) return next(`client with id ${ query.client_id } not found.`);
      req.session.client_id = client.id
      req.session.client_secret = client.secret // TODO: really needed?
      return next()
    })
  }

  _useState() {
    return (req, res, next) => {
      req.state = this.options.state
      next()
    }
  }

  auth() {
    return [ this._validateAuth, this._useState(), this._performAuth ];
  }

}

module.exports = OAuth2OIDC;
module.exports.state = {
  defaultSpecifications: require('./lib/specifications')
}
