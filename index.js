var OAuth2OIDC = function(options) {
  this.options = options || {};
}

OAuth2OIDC.prototype.auth = function() {
  return [ function(req, res, next) {
    console.log('validate...');
    next();
  }, function(req, res, next) {
    console.log('do it');
    next();
  }];
};
module.exports = OAuth2OIDC;
