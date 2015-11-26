'use strict';

const Waterline = require('waterline')
exports.getDefaultStateConfig = function(specifications, waterlineAdapter, connection, cb) {

  connection = connection || { adapter: 'adapter1' }

  const waterline = new Waterline();
  for (var name in specifications) {
    let model = specifications[name]
    model.connection = 'default'
    const collection = Waterline.Collection.extend(model)
    waterline.loadCollection(collection)
  }
  const config = {
    adapters: {
      adapter1: waterlineAdapter
    },
    connections: {
      default: connection
    }
  }
  waterline.initialize(config, cb)
}
