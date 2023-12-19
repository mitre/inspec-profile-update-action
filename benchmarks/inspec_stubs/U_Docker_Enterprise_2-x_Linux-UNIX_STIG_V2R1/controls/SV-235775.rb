control 'SV-235775' do
  title 'The Docker Enterprise Per User Limit Login Session Control in the Universal Control Plane (UCP) Admin Settings must be set to an organization-defined value for all accounts and/or account types.'
  desc 'The UCP component of Docker Enterprise includes a built-in access authorization mechanism called eNZi which can be integrated with an LDAP server and subsequently configured to limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types. Per-user session control limits are configured with a default of 10. For reference, the per user limit in UCP specifies the maximum number of sessions that any user can have active at any given time. If creating a new session would put a user over this limit then the least recently used session will be deleted. A value of zero disables limiting the number of sessions that users may have. This configuration applies to both the UCP and DTR management consoles.'
  desc 'check', %q(Check that the "Per User Limit" Login Session Control in the UCP Admin Settings is set according to the values defined in the System Security Plan.

via UI:

In the UCP web console, navigate to "Admin Settings" | "Authentication & Authorization" and verify the "Per User Limit" field is set according to the number specified in the System Security Plan.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine with connectivity to the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml|grep per_user_limit

If the "per_user_limit" entry under the "[auth.sessions]" section in the output is not set according to the value defined in the SSP, this is a finding.)
  desc 'fix', %q(Set the "Per User Limit" Login Session Control in the UCP Admin Settings per the requirements set forth by the System Security Plan (SSP).

via UI:

In the UCP web console, navigate to "Admin Settings" | "Authentication & Authorization" and set the "Per User Limit" field according to the requirements of this control.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands on either a UCP Manager node or using a UCP client bundle. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml > ucp-config.toml

Open the "ucp-config.toml" file, set the "per_user_limit" entry under the "[auth.sessions]" section according to the requirements of this control. Save the file.

Execute the following commands to update UCP with the new configuration:

curl -sk -H "Authorization: Bearer $AUTHTOKEN" --upload-file ucp-config.toml https://[ucp_url]/api/ucp/config-toml)
  impact 0.3
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-38994r627450_chk'
  tag severity: 'low'
  tag gid: 'V-235775'
  tag rid: 'SV-235775r627452_rule'
  tag stig_id: 'DKER-EE-001000'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-38957r627451_fix'
  tag 'documentable'
  tag legacy: ['SV-104693', 'V-94863']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
