"use strict";

const OAuth2OIDC = require('../..'),
      Waterline = require('waterline'),
      sailsMemoryAdapter = require('sails-memory')

global.OAuth2OIDC = OAuth2OIDC

function getStateConfig(cb) {
  // set up persistence: waterline with memory adapter
  const specifications = OAuth2OIDC.state.defaultSpecifications
  const waterline = new Waterline();
  for (var name in specifications) {
    let model = specifications[name]
    model.connection = 'default'
    const collection = Waterline.Collection.extend(model)
    waterline.loadCollection(collection)
  }
  const config = {
    adapters: {
      memory: sailsMemoryAdapter
    },
    connections: {
      default: {
        adapter: 'memory'
      }
    }
  }
  waterline.initialize(config, cb)
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
