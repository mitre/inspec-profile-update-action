import { exec } from 'child_process';

const axios = require('axios');
const fs = require('fs');
const saf = require('@mitre/saf')

// Find current version
const version = fs.readFileSync('/github/workspace/VERSION', 'utf-8');
//const version = 'V2R6'
console.log(`Current version: ${version}`);

const profile = process.env.profile

let foundProfile = false

export async function downloadFile(fileUrl, outputLocationPath) {
    const writer = fs.createWriteStream(outputLocationPath);
  
    return axios.get(fileUrl, {responseType: 'stream'}).then(response => {
  
      //ensure that the user can call `then()` only when the file has
      //been downloaded entirely.
  
      return new Promise((resolve, reject) => {
        response.data.pipe(writer);
        let error = null;
        writer.on('error', err => {
          error = err;
          writer.close();
          reject(err);
        });
        writer.on('close', () => {
          if (!error) {
            resolve(true);
          }
        });
      });
    });
  }

// Find latest version
axios.get(`https://raw.githubusercontent.com/mitre/inspec-profile-update-action/main/stigs.json`).then(({data}) => {
    data.forEach(stig => {
        if (stig.id === profile) {
            foundProfile = true;
            if (stig.version !== version) {
                console.log(`New version available: ${stig.version}`);
                // Check if profile.json is present
                if (!fs.existsSync('/github/workspace/profile.json')) {
                    throw new Error("profile.json is missing. Please generate one with `inspec profile . > profile.json`")
                } else {
                    // Download the latest STIG
                    downloadFile(stig.url, '/github/workspace/update.xccdf').then(() => {
                        exec('saf generate delta -i /github/workspace/ /github/workspace/profile.json /github/workspace/update.xccdf')
                    })
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