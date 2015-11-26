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
