control 'SV-215784' do
  title 'The BIG-IP Core implementation must be configured to deny-by-default all PKI-based authentication to virtual servers supporting path discovery and validation if unable to access revocation information via the network.'
  desc 'When revocation data is unavailable from the network, the system should be configured to deny-by-default to mitigate the risk of a user with a revoked certificate gaining unauthorized access. Local cached revocation data can be out of date or not able to be installed on the local system, which increases administration burden for the system.


The intent of this requirement is to deny unauthenticated users access to virtual servers in case access to OCSP (required by CCI-000185) is not available.

This requirement applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).'
  desc 'check', 'If the BIG-IP Core does not provide user authentication intermediary services for virtual servers, this is not applicable.

When user authentication intermediary services are provided, verify the BIG-IP Core is configured to deny-by-default user access when revocation information is not accessible via the network.

Navigate to the BIG-IP System manager >> Local Traffic >> Profiles >> SSL >> Client.

Select an SSL client profile that is used for client authentication with Virtual Server(s).

Review the configuration under the "Client Authentication" section.

Verify that "Client Certificate" is set to "require" if not using the APM.

Verify that “On Demand Cert Auth” in the access profile is set to “Require” if using APM.

If the BIG-IP Core is not configured to deny-by-default when unable to access revocation information via the network, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the BIG-IP Core to deny-by-default when access to revocation information via the network is inaccessible.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16976r291165_chk'
  tag severity: 'medium'
  tag gid: 'V-215784'
  tag rid: 'SV-215784r557356_rule'
  tag stig_id: 'F5BI-LT-000203'
  tag gtitle: 'SRG-NET-000345-ALG-000099'
  tag fix_id: 'F-16974r291166_fix'
  tag 'documentable'
  tag legacy: ['V-60349', 'SV-74779']
  tag cci: ['CCI-001991']
  tag nist: ['IA-5 (2) (d)']
end
