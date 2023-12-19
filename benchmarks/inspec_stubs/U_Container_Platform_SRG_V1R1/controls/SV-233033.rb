control 'SV-233033' do
  title 'The container platform must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage and conditions and take explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to any container platform component. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law. 

To establish acceptance of the application usage policy, a click-through banner at application logon is required. The application must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".'
  desc 'check', 'Log in to the container platform components to determine if the Standard Mandatory DoD Notice and Consent Banner remains on the screen until users acknowledge the usage and conditions and take explicit actions to log on for further access. 

If the Standard Mandatory DoD Notice and Consent Banner does not stay on the screen until the users acknowledge the usage and conditions, this is a finding.'
  desc 'fix', 'Configure the container platform to retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage and conditions and take explicit actions to log on for further access.'
  impact 0.3
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-35969r599518_chk'
  tag severity: 'low'
  tag gid: 'V-233033'
  tag rid: 'SV-233033r599519_rule'
  tag stig_id: 'SRG-APP-000069-CTR-000125'
  tag gtitle: 'SRG-APP-000069'
  tag fix_id: 'F-35937r598736_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
