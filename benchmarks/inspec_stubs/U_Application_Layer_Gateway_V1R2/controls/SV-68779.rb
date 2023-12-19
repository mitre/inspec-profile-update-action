control 'SV-68779' do
  title 'The ALG providing PKI-based user authentication intermediary services must map authenticated identities to the user account.'
  desc 'Authorization for access to any network element requires an approved and assigned individual account identifier. To ensure only the assigned individual is using the account, the account must be bound to a user certificate when PKI-based authentication is implemented.

This requirement applies to ALGs that provide user authentication intermediary services (e.g., authentication gateway or TLS gateway). This does not apply to authentication for the purpose of configuring the device itself (device management).'
  desc 'check', 'If the ALG does not provide PKI-based user authentication intermediary services, this is not applicable.

Verify the ALG maps the authenticated identity to the user account for PKI-based authentication.

If the ALG does not map the authenticated identity to the user account for PKI-based authentication, this is a finding.'
  desc 'fix', 'If PKI-based user authentication intermediary services are provided, configure the ALG to map the authenticated identities to the user account.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55149r2_chk'
  tag severity: 'medium'
  tag gid: 'V-54533'
  tag rid: 'SV-68779r1_rule'
  tag stig_id: 'SRG-NET-000166-ALG-000101'
  tag gtitle: 'SRG-NET-000166-ALG-000101'
  tag fix_id: 'F-59387r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
