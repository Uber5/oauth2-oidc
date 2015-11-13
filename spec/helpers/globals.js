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

let idCounter = 1
global.nextId = () => {
  return idCounter++
}

global.createRequest = function(options) {
  const defaults = {
    method: 'GET',
    url: '/whatever',
    query: {},
    params: {}
  }
  const effectiveOptions = Object.assign({}, defaults, options)
  return httpMocks.createRequest(effectiveOptions)
};

global.createResponse = function() {
  return httpMocks.createResponse();
};

