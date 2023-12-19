control 'SV-207411' do
  title 'The VMM must reveal system error messages only to authorized users.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the VMM or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the VMM is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the VMM reveals system error messages only to authorized users.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to reveal system error messages only to authorized users.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7668r365643_chk'
  tag severity: 'medium'
  tag gid: 'V-207411'
  tag rid: 'SV-207411r379108_rule'
  tag stig_id: 'SRG-OS-000206-VMM-000770'
  tag gtitle: 'SRG-OS-000206'
  tag fix_id: 'F-7668r365644_fix'
  tag 'documentable'
  tag legacy: ['V-57023', 'SV-71283']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
