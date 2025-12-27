control 'SV-235778' do
  title 'The audit log configuration level must be set to request in the Universal Control Plane (UCP) component of Docker Enterprise.'
  desc %q(The UCP and Docker Trusted Registry (DTR) components of Docker Enterprise provide audit record generation capabilities. Audit logs capture all HTTP actions for the following endpoints: Kubernetes API, Swarm API and UCP API. The following UCP API endpoints are excluded from audit logging (where "*" designates a wildcard of exclusions): "/_ping", "/ca", "/auth", "/trustedregistryca", "/kubeauth", "/metrics", "/info", "/version*", "/debug", "/openid_keys", "/apidocs", "kubernetesdocs" and "/manage". Audit log verbosity can be set to one of the following levels: "none", "metadata", or "request". To meet the requirements of this control, the "request" verbosity level must be configured in UCP.

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

The Docker Engine - Enterprise component of Docker Enterprise relies on the underlying host operating system's auditing capabilities. By default, the host OS is not configured to audit Docker Engine - Enterprise.

)
  desc 'check', %q(This check only applies to the UCP component of Docker Enterprise.

Verify that the audit log configuration level in UCP is set to "request":

Via UI:

As a Docker EE Admin, navigate to "Admin Settings" | "Audit Logs" in the UCP management console, and verify "Audit Log Level" is set to "Request". If the audit log configuration level is not set to "Request", this is a finding.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine that can communicate with the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml

Look for the "level" entry under the "[audit_log_configuration]" section in the output, and verify that it is set to "request".

If the "level" entry under the "[audit_log_configuration]" section in the output is not set to "request", then this is a finding.)
  desc 'fix', %q(This fix only applies to the UCP component of Docker Enterprise.

Set the remote syslog configuration in UCP:

via UI:

As a Docker EE Admin, navigate to "Admin Settings" | "Audit Logs" in the UCP management console, and set the "Audit Log Level" to "Request".

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine that can communicate with the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml > ucp-config.toml

Open the "ucp-config.toml" file under the "[audit_log_configuration]" section set "level = request". 
Save the file.

Execute the following commands to update UCP with the new configuration:

curl -sk -H "Authorization: Bearer $AUTHTOKEN" --upload-file ucp-config.toml https://[ucp_url]/api/ucp/config-toml)
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-38997r627459_chk'
  tag severity: 'medium'
  tag gid: 'V-235778'
  tag rid: 'SV-235778r627461_rule'
  tag stig_id: 'DKER-EE-001080'
  tag gtitle: 'SRG-APP-000016'
  tag fix_id: 'F-38960r627460_fix'
  tag satisfies: ['SRG-APP-000016', 'SRG-APP-000089', 'SRG-APP-000515', 'SRG-APP-000510', 'SRG-APP-000509', 'SRG-APP-000508', 'SRG-APP-000507', 'SRG-APP-000506', 'SRG-APP-000505', 'SRG-APP-000504', 'SRG-APP-000503', 'SRG-APP-000502', 'SRG-APP-000501', 'SRG-APP-000500', 'SRG-APP-000499', 'SRG-APP-000498', 'SRG-APP-000497', 'SRG-APP-000496', 'SRG-APP-000495', 'SRG-APP-000494', 'SRG-APP-000493', 'SRG-APP-000492', 'SRG-APP-000484', 'SRG-APP-000447', 'SRG-APP-000381', 'SRG-APP-000343', 'SRG-APP-000101', 'SRG-APP-000100', 'SRG-APP-000099', 'SRG-APP-000098', 'SRG-APP-000097', 'SRG-APP-000096', 'SRG-APP-000095', 'SRG-APP-000093', 'SRG-APP-000092', 'SRG-APP-000091']
  tag 'documentable'
  tag legacy: ['SV-104699', 'V-94869']
  tag cci: ['CCI-000130', 'CCI-000067', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000169', 'CCI-000172', 'CCI-001462', 'CCI-001464', 'CCI-001851', 'CCI-001487', 'CCI-001814', 'CCI-002754', 'CCI-002723', 'CCI-002234']
  tag nist: ['AU-3 a', 'AC-17 (1)', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-12 a', 'AU-12 c', 'AU-14 (2)', 'AU-14 (1)', 'AU-4 (1)', 'AU-3 f', 'CM-5 (1)', 'SI-10 (3)', 'SI-7 (8)', 'AC-6 (9)']
end
