control 'SV-71163' do
  title 'The operating system must reveal error messages only to authorized users.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the operating system reveals error messages only to authorized users. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to reveal error messages only to authorized users.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57473r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56903'
  tag rid: 'SV-71163r1_rule'
  tag stig_id: 'SRG-OS-000206-GPOS-00084'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-61799r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
