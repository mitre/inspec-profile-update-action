control 'SV-29582' do
  title 'Disallow AutoPlay/Autorun from Autorun.inf'
  desc 'This registry key will prevent the autorun.inf from executing commands.'
  desc 'fix', 'Add the registry value as specified in the manual check.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag severity: 'high'
  tag gid: 'V-17900'
  tag rid: 'SV-29582r1_rule'
  tag gtitle: 'Disallow AutoPlay/Autorun from Autorun.inf'
  tag fix_id: 'F-18240r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
