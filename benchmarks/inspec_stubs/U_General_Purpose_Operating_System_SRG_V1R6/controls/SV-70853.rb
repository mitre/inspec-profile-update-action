control 'SV-70853' do
  title 'The operating system must display the Standard Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to the operating system. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law.

To establish acceptance of the application usage policy, a click-through banner at system logon is required. The system must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".'
  desc 'check', 'Verify the operating system displays the Standard Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions and take explicit actions to log on for further access. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to display the Standard Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57163r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56593'
  tag rid: 'SV-70853r1_rule'
  tag stig_id: 'SRG-OS-000024-GPOS-00007'
  tag gtitle: 'SRG-OS-000024-GPOS-00007'
  tag fix_id: 'F-61489r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
