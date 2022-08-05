const {
    execSync
} = require('child_process');
const axios = require('axios');
const fs = require('fs');

// Find current version
const version = fs.readFileSync('/github/workspace/VERSION', 'utf-8');
//const version = 'V2R6'
console.log(`Current version: ${version}`);

const profile = process.env.profile

let foundProfile = false


// Find latest version
axios.get(`https://raw.githubusercontent.com/mitre/inspec-profile-update-action/main/stigs.json`).then(({
    data
}) => {
    data.forEach(stig => {
        if (stig.id === profile) {
            foundProfile = true;
            if (stig.version !== version) {
                console.log(`New version available: ${stig.version}`);
                // Check if profile.json is present
                if (!fs.existsSync('/github/workspace/profile.json')) {
                    throw new Error("profile.json is missing. Please generate one with `inspec profile . > profile.json`")
                } else {
                    console.log(execSync(`wget -O /github/workspace/update.xccdf ${stig.file}`))

                    execSync('mkdir /github/workspace/revisions/')
                    console.log(execSync('ls -lah /github/workspace/'))
                    if (process.env.identifier === 'group') {
                        console.log(execSync(`saf generate delta -i /github/workspace/ /github/workspace/profile.json /github/workspace/update.xccdf --useGroupID --logLevel debug --report "/github/workspace/revisions/${version.trim()}-to-${stig.version}.md"`))
                    } else if (process.env.identifier === 'stig') {
                        console.log(execSync(`saf generate delta -i /github/workspace/ /github/workspace/profile.json /github/workspace/update.xccdf --useStigID --logLevel debug --report "/github/workspace/revisions/${version.trim()}-to-${stig.version}.md"`))
                    } else if (process.env.identifier === 'cis') {
                        console.log(execSync(`saf generate delta -i /github/workspace/ /github/workspace/profile.json /github/workspace/update.xccdf --useCISId --logLevel debug --report "/github/workspace/revisions/${version.trim()}-to-${stig.version}.md"`))
                    } else {
                        console.log(execSync(`saf generate delta -i /github/workspace/ /github/workspace/profile.json /github/workspace/update.xccdf --useVulnerabilityId --logLevel debug --report "/github/workspace/revisions/${version.trim()}-to-${stig.version}.md"`))
                    }
                    
                }
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