control 'SV-203664' do
  title 'The operating system must reveal error messages only to authorized users.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the operating system reveals error messages only to authorized users. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to reveal error messages only to authorized users.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3789r557237_chk'
  tag severity: 'medium'
  tag gid: 'V-203664'
  tag rid: 'SV-203664r557239_rule'
  tag stig_id: 'SRG-OS-000206-GPOS-00084'
  tag gtitle: 'SRG-OS-000206'
  tag fix_id: 'F-3789r557238_fix'
  tag 'documentable'
  tag legacy: ['SV-71163', 'V-56903']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
