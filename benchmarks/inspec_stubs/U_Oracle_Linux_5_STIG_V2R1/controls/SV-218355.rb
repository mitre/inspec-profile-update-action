control 'SV-218355' do
  title 'All shell files must have mode 0755 or less permissive.'
  desc 'Shells with world/group write permissions give the ability to maliciously modify the shell to obtain unauthorized access.'
  desc 'check', 'If /etc/shells exists, check the group ownership of each shell referenced.
# cat /etc/shells | xargs -n1 ls -l

Otherwise, check any shells found on the system.
# find / -name "*sh" | xargs -n1 ls -l

If a shell has a mode more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the shell.
# chmod 0755 <shell>'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19830r569032_chk'
  tag severity: 'high'
  tag gid: 'V-218355'
  tag rid: 'SV-218355r603259_rule'
  tag stig_id: 'GEN002220'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19828r569033_fix'
  tag 'documentable'
  tag legacy: ['V-922', 'SV-63713']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
