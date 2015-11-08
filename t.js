"use strict";

const Waterline = require('waterline'),
      sailsMemoryAdapter = require('sails-memory'),
      specifications = require('./lib/specifications')

const waterline = new Waterline();

[ 'client', 'user' ].forEach((name) => {
  const model = Object.assign({}, specifications.models[name])
  model.connection = 'default'
  const collection = Waterline.Collection.extend(model)
  waterline.loadCollection(collection)
})

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
waterline.initialize(config, function(err, ontology) {
  if (err) return console.error(err);

  var Client = ontology.collections.client
  // console.log('Client.findOne', Client.findOne)
  Client.create({
    key: '123',
    secret: '234',
    name: 'some client',
    redirect_uris: [ 'http://localhost:9999' ]
  }).then((newClient) => {
    Client.findOne({ key: '123' }).exec(function(err, model) {
      console.log('findOne', err, model)
    })
  })
})

/*
client.find({ id: 1 }).exec(function(err, model) {
  console.log('find', err, model)
})
*/
