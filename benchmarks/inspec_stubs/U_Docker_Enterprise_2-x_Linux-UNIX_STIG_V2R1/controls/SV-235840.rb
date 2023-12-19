control 'SV-235840' do
  title 'Vulnerability scanning must be enabled for all repositories in the Docker Trusted Registry (DTR) component of Docker Enterprise.'
  desc 'DTR can scan Docker images for vulnerabilities and this capability should be enabled to meet the requirements of this control.

When enabled, for every Docker image that is pushed to DTR, a scan of each of the image layers is conducted. An analysis of all packages and compiled binaries is done for each image layer and if a package or binary is associated with a known vulnerability as identified by the MITRE CVE or NIST NVD databases, then it is flagged in DTR.'
  desc 'check', 'This check only applies to the DTR component of Docker Enterprise.

Check image vulnerability scanning enabled for all repositories:

via UI:

As a Docker EE Admin, navigate to "System" | "Security" in the DTR management console. Verify that the "Enable Scanning" slider is turned on and that the vulnerability database has been successfully synced (online)/uploaded (offline).

If "Enable Scanning" is tuned off or if the vulnerability database is not synced or uploaded, this is a finding.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine with connectivity to the DTR management console:

AUTHTOKEN=$(curl -sk -u <username>:<password> "https://[dtr_url]/auth/token" | jq -r .token)
curl -k -H "Authorization: Bearer $AUTHTOKEN" -X GET "https://[dtr_url]/api/v0/imagescan/status"

Verify that that the response is successful with HTTP Status Code 200, and look for the "lastDBUpdateFailed" and "lastVulnOverridesDBUpdateFailed" properties in the "Response body", and verify that are both "false".

If they are both not "false", this is a finding.'
  desc 'fix', %q(This fix only applies to the DTR component of Docker Enterprise.

Enable vulnerability scanning:

via UI:

As a Docker EE Admin, navigate to "System" | "Security" in the DTR management console. Click the "Enable Scanning" slider to enable this capability. Sync (online) or upload (offline) the vulnerability database.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine with connectivity to the DTR management console:

AUTHTOKEN=$(curl -sk -u <username>:<password> "https://[dtr_url]/auth/token" | jq -r .token)
curl -k -H "Authorization: Bearer $AUTHTOKEN" -X POST -d '{"scanningEnabled":true}' -H 'Content-Type: application/json' "https://[dtr_url]/api/v0/meta/settings"

If DTR is offline, upload the latest vulnerability database (retrievable via Docker Enterprise subscription):

AUTHTOKEN=$(curl -sk -u <username>:<password> "https://[dtr_url]/auth/token" | jq -r .token)
UPDATE_FILE="[path_to_cve_database].tar"
curl -k -H "Authorization: Bearer $AUTHTOKEN" -H "Content-Type: multipart/form-data" -H "Accept: application/json" -X PUT -F upload=@${UPDATE_FILE} "https://[dtr_url]/api/v0/imagescan/scan/update?online=false")
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39059r627645_chk'
  tag severity: 'medium'
  tag gid: 'V-235840'
  tag rid: 'SV-235840r627647_rule'
  tag stig_id: 'DKER-EE-003840'
  tag gtitle: 'SRG-APP-000414'
  tag fix_id: 'F-39022r627646_fix'
  tag 'documentable'
  tag legacy: ['SV-104851', 'V-95713']
  tag cci: ['CCI-001067']
  tag nist: ['RA-5 (5)']
end
