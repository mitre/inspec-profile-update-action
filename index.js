const axios = require('axios');
const fs = require('fs');

// Find current version
const version = fs.readFileSync('/github/workspace/VERSION', 'utf-8');
console.log(`Current version: ${version}`);

console.log(process.argv)
