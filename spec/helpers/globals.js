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

/** the below adds more text output, but 'conflicts' with the default
 * reporter, see jasmine/lib/jasmine.js */
jasmine.getEnv().addReporter(new reporters.TerminalReporter({
  verbosity: 3,
  color: true,
  showStack: true
}))

/** weirdly, the below exception handler influences how errors are reported by
 * Jasmine: Without this error handler, exceptions in `beforeEach` functions
 * are *not* reported. */
process.on('uncaughtException', (err) => {
  console.error('[specs] Uncaught error', err)
  if (err.stack) {
    console.error('[specs] Stack Trace', err.stack)
  }
})

global.OAuth2OIDC = OAuth2OIDC

function getStateConfig(cb) {
  return state.getDefaultStateConfig(
      OAuth2OIDC.state.defaultSpecifications,
      sailsMemoryAdapter,
      null,
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
  global['buildAndSave' + name] = ((factoryName) => {
    return (store, options) => {
      const result = factories.Factory.build(factoryName, options || {})
      if (!store[factoryName]) {
        console.log('factory ' + factoryName + ' not found', factories)
        throw new Error(`factory with name ${ factoryName } not found`);
      }
      return store[factoryName].create(result)
    }
  })(f)
}

global.getBasicClientAuthHeader = (client) => {
  return `Basic ${ new Buffer(client.key + ':' + client.secret).toString('base64') }`
}

global.buildUsableAccessToken = (factoryArguments, callback) => {
  let config, client, auth, refresh, user, access
  factoryArguments = factoryArguments || {}
  Promise.resolve(factoryArguments.config || buildTestConfig()).then((c) => {
    config = c
    return buildClient(factoryArguments.client)
  }).then((client) => {
    return config.state.collections.client.create(client)
  }).then((savedClient) => {
    client = savedClient
    return buildUser(factoryArguments['user'])
  }).then((user) => {
    debug('user', user)
    return config.state.collections.user.create(user)
  }).then((savedUser) => {
    debug('savedUser', savedUser)
    user = savedUser
    return buildAuth(Object.assign({}, { client: client, user: user  }))
  }).then((auth) => {
    debug('buildUsableAccessToken, auth', auth)
    return config.state.collections.auth.create(auth)
  }).then((savedAuth) => {
    auth = savedAuth
    return buildRefresh(Object.assign({}, { scope: client.scope, auth: auth }, factoryArguments.refresh ))
  }).then((refresh) => {
    debug('buildUsableAccessToken, refresh', refresh)
    return config.state.collections.refresh.create(refresh)
  }).then((savedRefresh) => {
    refresh = savedRefresh
    return buildAccess(Object.assign({}, {
      user: user.id,
      client: client.id,
      refresh_token: refresh.token
    }, factoryArguments['access']))
  }).then((acc) => {
    debug('acc', acc)
    return config.state.collections.access.create(acc)
  }).then((savedAccess) => {
    debug('savedAccess', savedAccess)
    access = savedAccess
    callback(null, {
      config: config,
      user: user,
      access: access,
      client: client
    })
  }).catch((err) => {
    debug('buildUsableAccessToken, err', err.stack)
    expect(err).toBeFalsy()
  })
}

global.express = express
