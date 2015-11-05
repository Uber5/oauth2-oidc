const validate = require('jsonschema').validate;

const OAuth2OIDC = function(options) {
  this.options = options || {};
}

const authSchema = {
  id: 'auth params',
  type: "object",
  response_type: { type: 'string' },
  client_id: { type: 'string' },
  scope: { type: 'string' },
  redirect_uri: { type: 'string' },
  required: [ 'response_type', 'client_id', 'scope', 'redirect_uri' ]
};

function displayableValidationErrors(errors) {
  return errors.map(function(e) { return e.message; }).join(', ');
}

function validateAuth(req, res, next) {

  var errors = validate(req.params, authSchema).errors;

  if (!errors.length) {
    return next();
  } else {
    return next(displayableValidationErrors(errors));
  }
}
OAuth2OIDC.prototype._validateAuth = validateAuth;

function performAuth(req, res, next) {
  console.log('do it');
  next('oops');
}
OAuth2OIDC.prototype._performAuth = performAuth;

OAuth2OIDC.prototype.auth = function() {
  return [ validateAuth, performAuth ];
};
module.exports = OAuth2OIDC;
