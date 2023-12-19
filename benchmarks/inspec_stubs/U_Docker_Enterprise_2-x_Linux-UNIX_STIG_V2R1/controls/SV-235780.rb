control 'SV-235780' do
  title 'LDAP integration in Docker Enterprise must be configured.'
  desc 'Both the Universal Control Plane (UCP) and Docker Trusted Registry (DTR) components of Docker Enterprise leverage the same authentication and authorization backplane known as eNZi. The eNZi backplane provides automated mechanisms for supporting account management functions and allows for LDAP integration in UCP and DTR. While eNZi includes its own managed user database, it is recommended that LDAP integration be configured to more completely satisfy the requirements of this control.

'
  desc 'check', %q(Verify that LDAP integration is enabled and properly configured in the UCP Admin Settings and verify that the LDAP/AD server is configured per the requirements set forth
in the appropriate OS STIG.

via UI:

In the UCP web console, navigate to "Admin Settings" | "Authentication & Authorization" and verify "LDAP Enabled" is set to "Yes" and that it is properly configured.

If it is not set to yes and if the LDAP server is not configured then this is a finding.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine with connectivity to the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml

Look for the "backend" entry under the "[auth]" section in the output, and verify that it is set to "ldap". *NOTE: For security reasons, the "[auth.ldap]" section is not stored in the config file and can only be viewed from the UCP Admin Settings UI.

If the "backend =" entry under the "[auth]" section in the output is not set to "ldap", then this is a finding.)
  desc 'fix', %q(Enable and configure LDAP integration in the UCP Admin Settings.

via UI:

In the UCP web console, navigate to "Admin Settings" | "Authentication & Authorization" and set "LDAP Enabled" to "Yes" and properly configure the LDAP/AD settings as per the appropriate OS STIG.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands on either a UCP Manager node or using a UCP client bundle. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml > ucp-config.toml

Open the "ucp-config.toml" file, set the "backend" entry under the "[auth]" section to "ldap", and add an "[auth.ldap]" sub-section per the UCP configuration options as documented at https://docs.docker.com/ee/ucp/admin/configure/ucp-configuration-file/#authldap-optional. Save the file.

Execute the following commands to update UCP with the new configuration:

curl -sk -H "Authorization: Bearer $AUTHTOKEN" --upload-file ucp-config.toml https://[ucp_url]/api/ucp/config-toml)
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-38999r627465_chk'
  tag severity: 'medium'
  tag gid: 'V-235780'
  tag rid: 'SV-235780r627467_rule'
  tag stig_id: 'DKER-EE-001100'
  tag gtitle: 'SRG-APP-000023'
  tag fix_id: 'F-38962r627466_fix'
  tag satisfies: ['SRG-APP-000023', 'SRG-APP-000405', 'SRG-APP-000404', 'SRG-APP-000403', 'SRG-APP-000401', 'SRG-APP-000397', 'SRG-APP-000392', 'SRG-APP-000148', 'SRG-APP-000141', 'SRG-APP-000391']
  tag 'documentable'
  tag legacy: ['SV-104703', 'V-95113']
  tag cci: ['CCI-000015', 'CCI-000381', 'CCI-000764', 'CCI-001954', 'CCI-001991', 'CCI-002010', 'CCI-002011', 'CCI-001953', 'CCI-002041', 'CCI-002014']
  tag nist: ['AC-2 (1)', 'CM-7 a', 'IA-2', 'IA-2 (12)', 'IA-5 (2) (d)', 'IA-8 (1)', 'IA-8 (2)', 'IA-2 (12)', 'IA-5 (1) (f)', 'IA-8 (4)']
end
