const crypto = require('crypto'),
  bcrypt = require('bcryptjs'),
  debug = require('debug')('oauth2-oidc'),
  validators = require('../validators')

function addCreatedAt(doc) {
  doc.createdAt = new Date();
  return doc;
}

module.exports = (url) => {

  const MongoClient = require('mongodb').MongoClient;
  const ObjectID = require('mongodb').ObjectID
  const pool = MongoClient.connect(url);

  function collection(name) {
    return pool
    .then(db => db.collection(name))
  }

  function genericCreate(collectionName) {
    debug('genericCreate, collectionName', collectionName)
    return object => validators[collectionName].validate(object)
      .then(validationResult => {
        if (validationResult.length) {
          debug(`validation on collection ${ collectionName }, invalid: ${ validationResult.join(', ') }`)
          throw new Error('validation failed: ' + validationResult.join(', '))
        }
        return collection(collectionName)
      })
      .then(collection => collection.insertOne(addCreatedAt(object)))
      .then(result => object)
  }

  function genericFindOne(collectionName) {
    return query => collection(collectionName)
      .then(collection => collection.findOne(query))
  }

  function genericSave(collectionName) {
    return object => collection(collectionName)
      .then(collection => {
        debug('genericSave', collectionName, object)
        return collection
      })
      .then(collection => collection.updateOne({ _id: object._id }, object))
      .then(() => object)
  }

  return {
    convertStringToId: s => new ObjectID(s),
    collections: {
      client: {
        findOne: function(query) {
          return collection('clients')
          .then(clients => clients.findOne(query))
        },
        create: function(client) {
          return collection('clients')
          .then(clients => clients.insertOne(addCreatedAt(client)))
          .then(() => client)
        },
        save: genericSave('clients'),
        deleteMany: function(query) {
          return collection('clients')
            .then(clients => clients.deleteMany(query))
        },
      },
      auth: {
        create: genericCreate('auths'),
        findOne: function(query) {
          return collection('auths')
          .then(auths => auths.findOne(query))
        },
        save: genericSave('auths'),
        deleteMany: query => collection('auths')
          .then(collection => collection.deleteMany(query))
      },
      access: {
        create: genericCreate('accessTokens'),
        findOne: function(query) {
          return collection('accessTokens')
          .then(accessTokens => accessTokens.findOne(query))
          .then(token => {
            debug('access.findOne, token', query, token);
            return token;
          })
        },
        save: genericSave('accessTokens'),
        deleteMany: query => collection('accessTokens')
          .then(collection => collection.deleteMany(query))
      },
      refresh: {
        create: function(refresh) {
          return collection('refreshTokens')
          .then(refreshTokens => refreshTokens.insert(addCreatedAt(refresh)))
          .then(result => refresh);
        },
        save: genericSave('refreshTokens'),
        findOne: genericFindOne('refreshTokens')
      },
      user: {
        create: function(user) {
          return collection('users')
          .then(users => users.insert(addCreatedAt(user)))
          .then(result => user)
        },
        findOne: query => genericFindOne('users')(query).then(user => {
          if (user) {
            user.samePassword = function(pwd) {
              const result = bcrypt.compareSync(pwd, user.password)
              return result
            }
          }
          return user
        }),
        save: genericSave('users'),
        validateAndCreate: function(user) {
          return Promise.resolve(user)
            .then(user => {
              if (!(user.password === user.passConfirm)) {
                throw new Error('password does not match confirmed password')
              }
              const preparedUser = Object.assign({}, user)
              preparedUser.password = bcrypt.hashSync(user.password)
              delete preparedUser.passConfirm
              return preparedUser
            }).then(preparedUser => genericCreate('users')(preparedUser))
        }
      }
    }
  }
}
