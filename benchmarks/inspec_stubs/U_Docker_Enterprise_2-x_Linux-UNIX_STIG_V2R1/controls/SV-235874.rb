control 'SV-235874' do
  title 'Docker Enterprise Universal Control Plane (UCP) must be configured to use TLS 1.2.'
  desc 'By default docker UCP is configured to use TLS v1.2, if this setting is misconfigured, older protocols containing security weaknesses could be utilized. TLS requires a handshake between client and server which is where the TLS version utilized in the connection is negotiated. For DoD use cases, all TLS must be at version 1.2.'
  desc 'check', %q(This check only applies to the UCP component of Docker Enterprise.

Via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine that can communicate with the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml

Look for the "min_TLS_version =" entry under the "[cluster_config]" section in the output, and verify that it is set to "TLSv1.2".

If the "min_TLS_version" entry under the "[cluster_config]" section in the output is not set to "TLSv1.2", then this is a finding.)
  desc 'fix', %q(This fix only applies to the UCP component of Docker Enterprise.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine that can communicate with the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml > ucp-config.toml

Open the "ucp-config.toml" file under the "[cluster_config]" section set "min_TLS_version = TLSv1.2". 
Save the file.

Execute the following commands to update UCP with the new configuration:

curl -sk -H "Authorization: Bearer $AUTHTOKEN" --upload-file ucp-config.toml https://[ucp_url]/api/ucp/config-toml)
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39093r627747_chk'
  tag severity: 'medium'
  tag gid: 'V-235874'
  tag rid: 'SV-235874r627749_rule'
  tag stig_id: 'DKER-EE-006280'
  tag gtitle: 'SRG-APP-000560'
  tag fix_id: 'F-39056r627748_fix'
  tag 'documentable'
  tag legacy: ['SV-104923', 'V-95785']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
