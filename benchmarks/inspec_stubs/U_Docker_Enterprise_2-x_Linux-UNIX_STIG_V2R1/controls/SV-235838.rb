control 'SV-235838' do
  title 'Content Trust enforcement must be enabled in Universal Control Plane (UCP) in Docker Enterprise.'
  desc 'The UCP and Docker Trusted Registry (DTR) components of Docker Enterprise can be used in concert to perform an integrity check of organization-defined software at startup. In the context of Docker Enterprise, software would be analogous to Docker images that have been pulled from trusted or untrusted sources. Docker Hub is the most common upstream endpoint for retrieving Docker images. However, only "Docker Certified" images on Docker Hub are considered trusted and come with SLAs and trusted signatures from their respective vendors. All other images from Docker Hub or other external registries must be carefully inspected and triaged prior to use. Docker Content Trust (DCT) provides for content integrity checking mechanisms on Docker images. DCT can be combined with LDAP, Docker Trusted Registry (DTR) and Universal Control Plane (UCP) to enforce image signatures from users/accounts in LDAP. Therefore, to meet the requirements of this control, it is imperative that UCP has LDAP integration enabled and that content trust enforcement is enabled and properly configured.

An operational requirement of this control is that of the required use of an established continuous integration and deployment workflow that effectively dictates exactly what software is allowed to run on UCP.'
  desc 'check', %q(This check only applies to the UCP component of Docker Enterprise.

Check that UCP is configured to only run signed images by applicable Orgs and Teams.

via UI:

In the UCP web console, navigate to "Admin Settings" | "Docker Content Trust" and verify that "Run only signed images" is checked. Verify that the Orgs and Teams that images must be signed by in the dropdown that follows matches that of your organizational policies.

If "Run only signed images" box is not checked, this is a finding.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands on a machine that can communicate with the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml

Look for the "require_content_trust" entry under the "[trust_configuration]" section in the output, and verify that it is set to "true".
If require_content_trust is not set to true, this is a finding.)
  desc 'fix', %q(This fix only applies to the UCP component of Docker Enterprise.

Enable Content Trust enforcement in UCP.

via UI:

In the UCP web console, navigate to "Admin Settings" | "Docker Content Trust" and check the box next to "Run only signed images". Set the appropriate Orgs and Teams that images must be signed by in the dropdown that follows to match that of the organizational policies.

via CLI:

Linux: As a Docker EE Admin, execute the following commands on a machine that can communicate with the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator:

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml > ucp-config.toml

Open the "ucp-config.toml" file, set the "require_content_trust" entry under the "[trust_configuration]" section to "true". Save the file.

Execute the following commands to update UCP with the new configuration:

curl -sk -H "Authorization: Bearer $AUTHTOKEN" --upload-file ucp-config.toml https://[ucp_url]/api/ucp/config-toml)
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39057r627639_chk'
  tag severity: 'medium'
  tag gid: 'V-235838'
  tag rid: 'SV-235838r627641_rule'
  tag stig_id: 'DKER-EE-003590'
  tag gtitle: 'SRG-APP-000386'
  tag fix_id: 'F-39020r627640_fix'
  tag 'documentable'
  tag legacy: ['SV-104847', 'V-95709']
  tag cci: ['CCI-001774']
  tag nist: ['CM-7 (5) (b)']
end
