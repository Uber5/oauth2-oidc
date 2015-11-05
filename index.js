var OAuth2OIDC = function(options) {
  this.options = options || {};
}

function validateAuth(req, res, next) {
  console.log('validate...');
  if (req.params.x1) {
    return next();
  } else {
    return next('expected x1 param');
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
