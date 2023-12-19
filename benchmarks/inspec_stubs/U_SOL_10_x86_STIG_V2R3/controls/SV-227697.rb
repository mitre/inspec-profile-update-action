control 'SV-227697' do
  title 'All shell files must not have extended ACLs.'
  desc 'Shells with world/group write permissions give the ability to maliciously modify the shell to obtain unauthorized access.'
  desc 'check', 'If /etc/shells exists, check the permissions of each shell referenced.
# cat /etc/shells | xargs -n1 ls -lL

Otherwise, check any shells found on the system.
# find / -name "*sh" | xargs -n1 ls -lL

If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [shell]'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29859r488672_chk'
  tag severity: 'medium'
  tag gid: 'V-227697'
  tag rid: 'SV-227697r603266_rule'
  tag stig_id: 'GEN002230'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29847r488673_fix'
  tag 'documentable'
  tag legacy: ['V-22366', 'SV-26492']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
