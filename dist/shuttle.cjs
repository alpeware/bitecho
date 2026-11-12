#!/usr/bin/env node
/**
 * Standalone zero-glue Node wrapper proxying all CLI commands directly to bitecho-light-node.cjs.
 * Supports offline bundle transport verbs (`export-poll`, `import-poll`, `import`, `export-offer`,
 * `export-send`, `export-ack`, `wait`, etc.) and live daemon commands (`ctl <subverb>`).
 */

const path = require('node:path');
const { spawnSync } = require('node:child_process');

const bundlePath = path.resolve(__dirname, 'bitecho-light-node.cjs');
const args = process.argv.slice(2);

const result = spawnSync(process.execPath, [bundlePath, ...args], {
  stdio: 'inherit',
  env: process.env
});

process.exit(result.status !== null ? result.status : (result.signal ? 1 : 0));
