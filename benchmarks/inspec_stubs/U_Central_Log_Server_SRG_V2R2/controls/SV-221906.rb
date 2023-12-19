control 'SV-221906' do
  title 'The Central Log Server must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to the application. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law. 

To establish acceptance of the application usage policy, a click-through banner at application logon is required. The application must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".'
  desc 'check', 'Examine the configuration.

Verify that the Central Log Server is configured to retain the Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions.

If the Central Log Server is not configured to retain the Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to retain the Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-23621r420060_chk'
  tag severity: 'low'
  tag gid: 'V-221906'
  tag rid: 'SV-221906r420062_rule'
  tag stig_id: 'SRG-APP-000069-AU-000420'
  tag gtitle: 'SRG-APP-000069'
  tag fix_id: 'F-23610r420061_fix'
  tag 'documentable'
  tag legacy: ['SV-109143', 'V-100039']
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
