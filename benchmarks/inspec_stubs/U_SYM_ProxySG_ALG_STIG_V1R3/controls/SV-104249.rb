control 'SV-104249' do
  title 'Symantec ProxySG, when configured for reverse proxy/WAF services and providing PKI-based user authentication intermediary services, must map the client certificate to the authentication server store.'
  desc 'Authorization for access to any network element requires an approved and assigned individual account identifier. To ensure only the assigned individual is using the account, the account must be bound to a user certificate when PKI-based authentication is implemented.

This requirement applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). It does not apply to authentication for the purpose of configuring the device itself (device management).'
  desc 'check', %q(Verify that PKI user credentials map identities to the user account name in a reverse proxy configuration.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Services >> Proxy Services.
3. Click each HTTPS Reverse Proxy service and click "Edit Service".
4. Verify that "Verify Client" is checked. Verify that all remaining options are in accordance with the site's SSP.

If Symantec ProxySG, when configured for reverse proxy/WAF services and providing PKI-based user authentication intermediary services, does not map the client certificate to the authentication server store, this is a finding.)
  desc 'fix', %q(Configure the ProxySG to map PKI user credentials to user identities in a reverse proxy configuration.

1. Log on to the Web Management Console.
2. Browse to Configuration >> Services >> Proxy Services.
3. Click each HTTPS Reverse Proxy service and click "Edit Service".
4. Check the "Verify Client" option and click "Apply".
5. Configure all remaining options in accordance with the site's SSP.)
  impact 0.5
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93481r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94295'
  tag rid: 'SV-104249r1_rule'
  tag stig_id: 'SYMP-AG-000410'
  tag gtitle: 'SRG-NET-000166-ALG-000101'
  tag fix_id: 'F-100411r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
