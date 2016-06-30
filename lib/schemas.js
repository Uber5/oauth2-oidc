const validate = require('jsonschema').validate;

exports.authSchema = {
  id: 'auth params',
  type: "object",
  response_type: { type: 'string' },
  client_id: { type: 'string' },
  scope: { type: 'string' },
  redirect_uri: { type: 'string' },
  required: [ 'response_type', 'client_id', 'redirect_uri' ]
}

exports.configSchema = {
  id: 'configuration',
  type: 'object',
  state: {
    type: 'object',
    client: { type: 'string' },
    required: [ 'client' ]
  },
  required: [ 'state', 'login_url' ]
}

exports.displayableValidationErrors = function(errors) {
  return errors.map(function(e) { return e.message; }).join(', ');
}

exports.validationErrors = function(what, schema) {
  var errors = validate(what, schema).errors
  if (errors.length) {
    return exports.displayableValidationErrors(errors)
  } else {
    return;
  }
}

exports.validate = validate
