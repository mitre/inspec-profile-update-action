const axios = require('axios');
const fs = require('fs');

// Find current version
//const version = fs.readFileSync('/github/workspace/VERSION', 'utf-8');
const version = 'V2R6'
console.log(`Current version: ${version}`);

const profile = process.env.profile

let foundProfile = false

// Find latest version
axios.get(`https://raw.githubusercontent.com/mitre/inspec-profile-update-action/main/stigs.json`).then(({data}) => {
    data.forEach(stig => {
        if (stig.id === profile) {
            foundProfile = true;
            console.log(`Latest version: ${stig.version}`);
            if (stig.version !== version) {
                console.log(`New version available: ${stig.version}`);
            } else {
                console.log(`No new version available.`);
            }
        }
    })
}).then(() => {
    if (!foundProfile) {
        throw new Error(`Benchmark ID ${profile} not found.`);
    }
})