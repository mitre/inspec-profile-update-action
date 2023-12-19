control 'SV-222435' do
  title 'The application must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to the application. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DoD will not be in compliance with system use notifications required by law.

To establish acceptance of the application usage policy, a click-through banner at application logon is required. The application must prevent further activity until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".'
  desc 'check', 'If the application has no interactive user interface, this requirement is not applicable.

If the user interface is only available via the OS console, e.g., a fat client application installed on a GFE desktop or laptop, and that GFE is configured to display the DoD banner, this requirement is not applicable.

Access the application and authenticate if necessary. Verify the banner is displayed and action must be taken to accept terms of use.

If the banner is not displayed or no action must be taken to accept terms of use, this is a finding.'
  desc 'fix', 'Configure the application to retain the standard DoD-approved banner until the user accepts the usage conditions prior to granting access to the application.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24105r493213_chk'
  tag severity: 'low'
  tag gid: 'V-222435'
  tag rid: 'SV-222435r508029_rule'
  tag stig_id: 'APSC-DV-000560'
  tag gtitle: 'SRG-APP-000069'
  tag fix_id: 'F-24094r493214_fix'
  tag 'documentable'
  tag legacy: ['V-69351', 'SV-83973']
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
