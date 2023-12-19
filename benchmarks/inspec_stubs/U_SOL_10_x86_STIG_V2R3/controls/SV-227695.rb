control 'SV-227695' do
  title 'All shell files must be group-owned by root, bin, or sys.'
  desc 'If shell files are group-owned by users other than root or a system group, they could be modified by intruders or malicious users to perform unauthorized actions.'
  desc 'check', 'If /etc/shells exists, check the group ownership of each shell referenced.

Procedure:
# cat /etc/shells | xargs -n1 ls -lL

Otherwise, check any shells found on the system.
Procedure:
# find / -name "*sh" | xargs -n1 ls -lL

If a shell is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group-owner of the shell to root, bin, or sys.

Procedure:
# chgrp root <shell>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29857r488666_chk'
  tag severity: 'medium'
  tag gid: 'V-227695'
  tag rid: 'SV-227695r603266_rule'
  tag stig_id: 'GEN002210'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29845r488667_fix'
  tag 'documentable'
  tag legacy: ['V-22365', 'SV-39902']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
