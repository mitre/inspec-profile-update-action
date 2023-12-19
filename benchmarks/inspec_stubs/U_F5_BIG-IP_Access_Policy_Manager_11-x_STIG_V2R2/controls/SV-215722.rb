control 'SV-215722' do
  title 'The BIG-IP APM module must map the authenticated identity to the user account for PKI-based authentication to virtual servers.'
  desc 'Authorization for access to any network element requires an approved and assigned individual account identifier. To ensure only the assigned individual is using the account, the account must be bound to a user certificate when PKI-based authentication is implemented.

This requirement applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).'
  desc 'check', 'If the BIG-IP APM module does not provide PKI-based, user authentication intermediary services, this is not applicable.

Verify the BIG-IP APM module maps the authenticated identity to the user account for PKI-based authentication.

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for an Access Profile used for PKI-based authentication.

Verify the Access Profile is configured to map the authenticated identity to the user account for PKI-based authentication.

If the BIG-IP APM module does not map the authenticated identity to the user account for PKI-based authentication, this is a finding.'
  desc 'fix', 'If the BIG-IP APM module provides PKI-based, user authentication intermediary services, configure a profile in the BIG-IP APM module to map the authenticated identity to the user account for PKI-based authentication.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-16915r290412_chk'
  tag severity: 'medium'
  tag gid: 'V-215722'
  tag rid: 'SV-215722r557355_rule'
  tag stig_id: 'F5BI-AP-000085'
  tag gtitle: 'SRG-NET-000166-ALG-000101'
  tag fix_id: 'F-16913r290413_fix'
  tag 'documentable'
  tag legacy: ['V-60035', 'SV-74465']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
