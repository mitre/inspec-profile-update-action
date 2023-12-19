control 'SV-3480' do
  title 'Media Player must be configured to prevent automatic checking for updates.'
  desc 'Uncontrolled system updates can introduce issues to a system. The automatic check for updates performed by Windows Media Player must be disabled to ensure a constant platform and to prevent the introduction of unknown\\untested software on the system.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> "Prevent Automatic Updates" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3480'
  tag rid: 'SV-3480r2_rule'
  tag gtitle: 'Media Player - Disable Automatic Updates'
  tag fix_id: 'F-45022r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCSL-1'
end
