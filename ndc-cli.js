#!/usr/bin/env node
const { execSync } = require('child_process');
execSync('./ndc', { stdio: 'inherit' });
