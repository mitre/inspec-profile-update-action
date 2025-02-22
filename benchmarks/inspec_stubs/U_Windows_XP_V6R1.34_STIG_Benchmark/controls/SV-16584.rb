control 'SV-16584' do
  title 'Prohibit Network Bridge in Windows'
  desc 'This check verifies the Network Bridge can not be installed and configured.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Network Connections “Prohibit installation and configuration of Network Bridge on your DNS domain network” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-15667'
  tag rid: 'SV-16584r1_rule'
  tag gtitle: 'Prohibit Network Bridge'
  tag fix_id: 'F-15533r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
