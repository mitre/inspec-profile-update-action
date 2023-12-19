control 'SV-204714' do
  title 'The application server management interface must retain the Standard Mandatory DoD Notice and Consent Banner on the screen until users acknowledge the usage conditions and take explicit actions to log on for further access.'
  desc 'To establish acceptance of system usage policy, a click-through banner at the application server management interface logon is required. The banner shall prevent further activity on the application server unless and until the user executes a positive action to manifest agreement by clicking on a box indicating "OK".'
  desc 'check', 'Review application server management interface product documentation and configuration to determine that the logon banner can be displayed until the user takes action to acknowledge the agreement.

If the banner screen allows continuation to the application server without user interaction, this is a finding.'
  desc 'fix', 'Configure the application server management interface to retain the logon banner on the screen until the user takes explicit action to logon to the server.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4834r282789_chk'
  tag severity: 'medium'
  tag gid: 'V-204714'
  tag rid: 'SV-204714r508029_rule'
  tag stig_id: 'SRG-APP-000069-AS-000036'
  tag gtitle: 'SRG-APP-000069'
  tag fix_id: 'F-4834r282790_fix'
  tag 'documentable'
  tag legacy: ['SV-46385', 'V-35098']
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']
end
