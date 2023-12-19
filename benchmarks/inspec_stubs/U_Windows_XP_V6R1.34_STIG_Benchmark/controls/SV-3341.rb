control 'SV-3341' do
  title 'Remote control of a Terminal Service session is allowed.'
  desc 'This setting is used to control the rules for remote control of Terminal Services user sessions.  This is a Category 1 finding because remote control of sessions could permit an unauthorized user to access sensitive information on the controlled system.'
  desc 'fix', 'Configure the system to prevent remote control of the computer by setting the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services, “Sets rules for remote control of Terminal Services user settings” to “Enabled” and the “Options” will be set to “No remote control allowed”.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag severity: 'high'
  tag gid: 'V-3341'
  tag rid: 'SV-3341r1_rule'
  tag gtitle: 'Terminal Service - Remote Control Settings'
  tag fix_id: 'F-126r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
