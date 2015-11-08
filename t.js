"use strict";

const Waterline = require('waterline'),
      sailsMemoryAdapter = require('sails-memory'),
      collections = require('./lib/collections')

const waterline = new Waterline()

const clientSchema = collections.models.client
clientSchema.connection = 'default'

const clientCollection = Waterline.Collection.extend(clientSchema)

waterline.loadCollection(clientCollection)
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
  console.log('Client.findOne', Client.findOne)
})

/*
client.find({ id: 1 }).exec(function(err, model) {
  console.log('find', err, model)
})
*/
