'use strict';

const Waterline = require('waterline')
exports.getDefaultStateConfig = function(specifications, waterlineAdapter, cb) {

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
      default: {
        adapter: 'adapter1'
      }
    }
  }
  waterline.initialize(config, cb)
}
