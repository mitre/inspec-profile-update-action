control 'SV-16601' do
  title 'Windows Installer – IE Security Prompt'
  desc 'This check verifies that users are notified if a web-based program attempts to install software.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer “Disable IE security prompt for Windows Installer scripts” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-15684'
  tag rid: 'SV-16601r1_rule'
  tag gtitle: 'Windows Installer – IE Security Prompt'
  tag fix_id: 'F-15551r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
