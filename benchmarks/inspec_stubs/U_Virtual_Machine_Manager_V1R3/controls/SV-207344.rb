control 'SV-207344' do
  title 'The VMM must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to the VMM. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law. 

To establish acceptance of the application usage policy, a click-through banner at system logon is required. The system must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".'
  desc 'check', 'Verify the VMM retains the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7601r365442_chk'
  tag severity: 'medium'
  tag gid: 'V-207344'
  tag rid: 'SV-207344r378523_rule'
  tag stig_id: 'SRG-OS-000024-VMM-000070'
  tag gtitle: 'SRG-OS-000024'
  tag fix_id: 'F-7601r365443_fix'
  tag 'documentable'
  tag legacy: ['V-56847', 'SV-71107']
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
