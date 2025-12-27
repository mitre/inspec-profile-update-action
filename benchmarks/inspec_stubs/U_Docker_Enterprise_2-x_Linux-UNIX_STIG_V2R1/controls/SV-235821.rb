control 'SV-235821' do
  title 'SAML integration must be enabled in Docker Enterprise.'
  desc 'Both the Universal Control Plane (UCP) and Docker Trusted Registry (DTR) components of Docker Enterprise leverage the same authentication and authorization backplane known as eNZi. The eNZi backplane includes its own managed user database, and also allows for LDAP and SAML integration in UCP and DTR. To meet the requirements of this control, configure LDAP and SAML integration.

'
  desc 'check', %q(Verify that SAML integration is enabled and properly configured in the UCP Admin Settings.

via UI:

In the UCP web console, navigate to "Admin Settings" | "Authentication & Authorization" and verify "SAML Enabled" is set to "Yes" and that it is properly configured. If SAML authentication is not enabled, this is a finding.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine with connectivity to the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml

Verify that the "samlEnabled" entry under the "[auth]" section is set to "true".

If the "samlEnabled" entry under the "[auth]" section is not set to "true", then this is a finding.)
  desc 'fix', %q(Enable and configure SAML integration in the UCP Admin Settings.

via UI:

In the UCP web console, navigate to "Admin Settings" | "Authentication & Authorization" and set "SAML Enabled" to "Yes" and properly configure the SAML settings.

via CLI:

Linux (requires curl and jq): As a Docker EE Admin, execute the following commands from a machine with connectivity to the UCP management console. Replace [ucp_url] with the UCP URL, [ucp_username] with the username of a UCP administrator and [ucp_password] with the password of a UCP administrator.

AUTHTOKEN=$(curl -sk -d '{"username":"[ucp_username]","password":"[ucp_password]"}' https://[ucp_url]/auth/login | jq -r .auth_token)
curl -sk -H "Authorization: Bearer $AUTHTOKEN" https://[ucp_url]/api/ucp/config-toml > ucp-config.toml

Open the "ucp-config.toml" file. Set the "samlEnabled" entry under the "[auth]" section to "true". Set the "idpMetadataURL" and "spHost" entries under the "[auth.saml]" to appropriate values per the UCP configuration options as documented at https://docs.docker.com/ee/ucp/admin/configure/ucp-configuration-file/#authsaml-optional. Save the file.

Execute the following commands to update UCP with the new configuration:

curl -sk -H "Authorization: Bearer $AUTHTOKEN" --upload-file ucp-config.toml https://[ucp_url]/api/ucp/config-toml)
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39040r627588_chk'
  tag severity: 'medium'
  tag gid: 'V-235821'
  tag rid: 'SV-235821r627590_rule'
  tag stig_id: 'DKER-EE-002180'
  tag gtitle: 'SRG-APP-000149'
  tag fix_id: 'F-39003r627589_fix'
  tag satisfies: ['SRG-APP-000149', 'SRG-APP-000150', 'SRG-APP-000151', 'SRG-APP-000152', 'SRG-APP-000153', 'SRG-APP-000391', 'SRG-APP-000392', 'SRG-APP-000402', 'SRG-APP-000403', 'SRG-APP-000404', 'SRG-APP-000405']
  tag 'documentable'
  tag legacy: ['SV-104815', 'V-95677']
  tag cci: ['CCI-000765', 'CCI-000766', 'CCI-000767', 'CCI-000768', 'CCI-000770', 'CCI-001953', 'CCI-001954', 'CCI-002011', 'CCI-002014', 'CCI-002009', 'CCI-002010']
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)', 'IA-2 (5)', 'IA-2 (12)', 'IA-2 (12)', 'IA-8 (2)', 'IA-8 (4)', 'IA-8 (1)', 'IA-8 (1)']
end
