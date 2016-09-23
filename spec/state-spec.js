'use strict';

const OAuth2OIDC = require('../');

describe('state (mongo implementation)', () => {
  const state = OAuth2OIDC.getStateBackedByMongoDB(process.env.MONGO_URL || 'mongodb://localhost/oauth2-oidc-test')
  it('has helpers', () => {
    expect(state.helpers).toBeTruthy()
  })
  it('has validators', () => {
    expect(state.validators).toBeTruthy()
    expect(state.validators.clients).toBeTruthy()
  })
})
