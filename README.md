[<img src="https://travis-ci.org/Uber5/oauth2-oidc.svg?branch=master">](https://travis-ci.org/Uber5/oauth2-oidc)

# Development

## Setup

Assuming you've got a NodeJS environment ready:

```
npm install
```

## Run Specs

```
npm test
```

## Run Specs Continuously

```
npm run watch
```

## Debug Specs

Run the specs with `--debug-brk` to make node wait for the debugger to attach:

```
node --debug-brk ./node_modules/jasmine/bin/jasmine.js
```

Run `node-inspector`:

```
./node_modules/.bin/node-inspector
```

... (does not work at the moment... why?)

# Testing

The example provider can be run with a REPL:

```
WITH_REPL=1 node examples/provider.js
```

Within the REPL, the following will be in the context: `provider`, `ontology`, `server`

This gives access to anything persisted like this:

```
ontology.collections.client.findOne({ id: 1 }).then((c) => { console.log('c', c) })
```

## Persistence

The example provider uses in-memory "persistence" by default. MongoDB can be
used instead by providing a url in environment variable `MONGO_URL` like so:

```
MONGO_URL=mongodb://localhost/oauth2-oidc-provider node examples/provider.js
```
