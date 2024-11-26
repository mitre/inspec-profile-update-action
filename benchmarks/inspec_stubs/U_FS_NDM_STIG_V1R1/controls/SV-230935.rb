control 'SV-230935' do
  title 'Forescout must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the administrator prior to the device allowing the administrator access to the network device. This provides assurance that the administrator has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the administrator, DoD will not be in compliance with system use notifications required by law. 

To establish acceptance of the network administration policy, a click-through banner at management session logon is required. The device must prevent further activity until the administrator executes a positive action to manifest agreement.

In the case of CLI access using a terminal client, entering the username and password when the banner is presented is considered an explicit action of acknowledgement. Entering the username, viewing the banner, then entering the password is also acceptable. The web management tool configuration setting works for both the CLI and the web management tool.'
  desc 'check', 'Verify Forescout retains the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and takes explicit actions to log on for further access.

Attempt to log on to the Forescout device as a system administrator using the web management tool.

If Forescout does not retain the Standard Mandatory DoD-approved Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access, this is a finding.'
  desc 'fix', 'Log on to the Forescout Administrator UI.

1. Select Tools >> Options >> CounterACT User Profiles >> Password and Sessions.
2.  Select the "Login" tab and check the "Display this Notice and Consent Message after login" option.
3. Select the "Before login, prompt user to accept these Terms and Conditions".
4. Select "Apply" to save the settings.'
  impact 0.3
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33865r615880_chk'
  tag severity: 'low'
  tag gid: 'V-230935'
  tag rid: 'SV-230935r615886_rule'
  tag stig_id: 'FORE-NM-000060'
  tag gtitle: 'SRG-APP-000069-NDM-000216'
  tag fix_id: 'F-33838r603645_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
