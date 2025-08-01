control 'SV-235847' do
  title 'Docker Content Trust enforcement must be enabled in Universal Control Plane (UCP).'
  desc %q(The UCP and Docker Trusted Registry (DTR) components of Docker Enterprise can be used in concert with built-in audit logging capabilities to audit detected potential integrity violations per the requirements set forth by the System Security Plan (SSP).

In the context of Docker Enterprise, software would be analogous to Docker images that have been pulled from trusted or untrusted sources. Docker Hub is the most common upstream endpoint for retrieving Docker images. However, only "Docker Certified" images on Docker Hub are considered trusted and come with SLAs and trusted signatures from their respective vendors. All other images from Docker Hub or other external registries must be carefully inspected and triaged prior to use. Docker Content Trust (DCT) provides for content integrity checking mechanisms on Docker images. DCT can be combined with LDAP, DTR and UCP to enforce image signatures from users/accounts in LDAP. Therefore, to meet the requirements of this control, it is imperative that UCP has LDAP integration enabled and that content trust enforcement is enabled and properly configured.

The UCP and DTR components of Docker Enterprise provide audit record generation capabilities. Audit logs capture all HTTP actions for the following endpoints: Kubernetes API, Swarm API and UCP API. The following UCP API endpoints are excluded from audit logging (where "*" designates a wildcard of exclusions): "/_ping", "/ca", "/auth", "/trustedregistryca", "/kubeauth", "/metrics", "/info", "/version*", "/debug", "/openid_keys", "/apidocs", "kubernetesdocs" and "/manage". Audit log verbosity can be set to one of the following levels: "none", "metadata", or "request". To meet the requirements of this control, the "request" verbosity level must be configured in UCP.

The data captured at each level for UCP and the eNZI authentication and authorization backplane is described below:

"none": audit logging is disabled

"metadata":
 - method and API endpoint for the request
 - UCP user which made the request
 - response status (success/failure)
 - timestamp of the call
 - object ID of created/updated resource (for create/update calls)
 - license key
 - remote address

"request": includes all fields from the "metadata" level, as well as the request payload

DTR audits all events associated with repository activities. Events are considered as follows: create, get, delete, update, send, fail, and scan. The following types are associated with the defined audit events: repository, tag, blob, manifest, webhook, uri, promotion, push mirroring, poll mirroring, garbage collector, system.

The Docker Engine - Enterprise component of Docker Enterprise relies on the underlying host operating system's auditing capabilities. By default, the host OS is not configured to audit Docker Engine - Enterprise.)
  desc 'check', %q(This check only applies to the UCP component of Docker Enterprise.

Check that UCP is configured to only run signed images by applicable Orgs and Teams.

via UI:

In the UCP web console, navigate to "Admin Settings" | "Docker Content Trust" and verify that "Run only signed images" is checked. Verify that the Orgs and Teams that images must be signed by in the dropdown that follows matches that of the organizational policies.

If "Run only signed images" is not checked, this is a finding.

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
  tag check_id: 'C-39066r627666_chk'
  tag severity: 'medium'
  tag gid: 'V-235847'
  tag rid: 'SV-235847r627668_rule'
  tag stig_id: 'DKER-EE-004370'
  tag gtitle: 'SRG-APP-000485'
  tag fix_id: 'F-39029r627667_fix'
  tag 'documentable'
  tag legacy: ['SV-104867', 'V-95729']
  tag cci: ['CCI-002724']
  tag nist: ['SI-7 (8)']
end
