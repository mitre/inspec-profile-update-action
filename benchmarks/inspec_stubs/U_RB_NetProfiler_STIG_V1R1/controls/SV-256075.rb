control 'SV-256075' do
  title 'The Riverbed NetProfiler must be configured to retain the Standard Mandatory DOD Notice and Consent Banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access.'
  desc 'The administrator must acknowledge the banner prior to the device allowing the administrator access to the network device. This provides assurance that the administrator has seen the message and accepted the conditions for access. If the administrator does not acknowledge the consent banner, DOD will not be in compliance with system use notifications required by law. 

To establish acceptance of the network administration policy, a click-through banner at management session logon is required. The device must prevent further activity until the administrator executes a positive action to manifest agreement.

In the case of CLI access using a terminal client, entering the username and password when the banner is presented is considered an explicit action of acknowledgement. Entering the username, viewing the banner, and then entering the password is also acceptable.'
  desc 'check', 'Go to Administration >> Account Management >> User Accounts. 

Click "Settings". 

Check under "Log-in Settings". 

If the "Log-in splash screen display" is not set to "Show until Acknowledged", this is a finding.'
  desc 'fix', 'Go to Administration >> Account Management >> User Accounts. 

Click "Settings". 

Under "Log-in Settings", on the "Log-in splash screen display", use the drop-down menu to select "Show until Acknowledged".'
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59749r882731_chk'
  tag severity: 'medium'
  tag gid: 'V-256075'
  tag rid: 'SV-256075r882733_rule'
  tag stig_id: 'RINP-DM-000010'
  tag gtitle: 'SRG-APP-000069-NDM-000216'
  tag fix_id: 'F-59692r882732_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
