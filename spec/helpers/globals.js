"use strict";

const OAuth2OIDC = require('../..'),
      Waterline = require('waterline'),
      sailsMemoryAdapter = require('sails-memory'),
      state = require('../../examples/state'),
      httpMocks = require('node-mocks-http')


global.OAuth2OIDC = OAuth2OIDC

function getStateConfig(cb) {
  return state.getDefaultStateConfig(
      OAuth2OIDC.state.defaultSpecifications,
      sailsMemoryAdapter,
      cb
  )
}

global.debug = require('debug')('oauth2-oidc')
global.testConfig = (cb) => {
  getStateConfig((err, ontology) => {
    if (err) throw new Error(err);
    cb(err, {
      state: ontology,
      login_url: '/login'
    })
  })
}

let usernameCounter = 1
global.nextUsername = () => {
  return `chris${ usernameCounter++ }`
}

global.createRequest = function(query) {
  return httpMocks.createRequest({
    method: 'GET',
      url: '/whatever',
      query: query
  });
};

global.createResponse = function() {
  return httpMocks.createResponse();
};

