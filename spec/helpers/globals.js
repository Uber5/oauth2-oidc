"use strict";

const OAuth2OIDC = require('../..'),
      Waterline = require('waterline'),
      sailsMemoryAdapter = require('sails-memory'),
      state = require('../../examples/state'),
      httpMocks = require('node-mocks-http'),
      factories = require('./factories'),
      S = require('string'),
      express = require('express'),
      reporters = require('jasmine-reporters')

jasmine.getEnv().addReporter(new reporters.TerminalReporter({
  verbosity: 3,
  color: true,
  showStack: true
}))

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
global.buildTestConfig = () => {
  return new Promise((res, rej) => {
    testConfig((err, cfg) => {
      if (err) return rej(err);
      res(cfg)
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

/** This provides us functions: given factory 'client', we'll have
 * 'buildClient' */
for (var f in factories) {
  const name = S('_' + f).camelize().s
  global['build' + name] = ((factoryName) => {
    return (options) => {
      const result = factories.Factory.build(factoryName, options || {})
      return result
    }
  })(f)
}

global.express = express
