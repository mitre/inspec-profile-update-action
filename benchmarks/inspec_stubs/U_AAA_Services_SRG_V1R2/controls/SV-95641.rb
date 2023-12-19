control 'SV-95641' do
  title 'AAA Services must be configured to map the authenticated identity to the user account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function.

Verify AAA Services are configured to map the authenticated identity to the user account for PKI-based authentication.

If AAA Services are not configured to map the authenticated identity to the user account, this is a finding.'
  desc 'fix', 'Configure AAA Services to map the authenticated identity to the user account for PKI-based authentication.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80669r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80931'
  tag rid: 'SV-95641r1_rule'
  tag stig_id: 'SRG-APP-000177-AAA-000600'
  tag gtitle: 'SRG-APP-000177-AAA-000600'
  tag fix_id: 'F-87787r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
