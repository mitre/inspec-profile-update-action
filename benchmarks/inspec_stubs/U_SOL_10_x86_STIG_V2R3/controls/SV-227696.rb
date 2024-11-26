control 'SV-227696' do
  title 'All shell files must have mode 0755 or less permissive.'
  desc 'Shells with world/group-write permissions give the ability to maliciously modify the shell to obtain unauthorized access.'
  desc 'check', 'If /etc/shells exists, check the group ownership of each shell referenced.
# cat /etc/shells | xargs -n1 ls -lL

Otherwise, check any shells found on the system.
# find / -name "*sh" | xargs -n1 ls -lL

If a shell has a mode more permissive than 0755, this is a finding.'
  desc 'fix', 'Change the mode of the shell.
# chmod 0755 <shell>'
  impact 0.7
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29858r488669_chk'
  tag severity: 'high'
  tag gid: 'V-227696'
  tag rid: 'SV-227696r603266_rule'
  tag stig_id: 'GEN002220'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29846r488670_fix'
  tag 'documentable'
  tag legacy: ['V-922', 'SV-922']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
