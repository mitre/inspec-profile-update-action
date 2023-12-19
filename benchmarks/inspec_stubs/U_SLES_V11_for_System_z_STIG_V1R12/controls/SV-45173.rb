control 'SV-45173' do
  title 'All shell files must be group-owned by root, bin, sys, or system.'
  desc 'If shell files are group-owned by users other than root or a system group, they could be modified by intruders or malicious users to perform unauthorized actions.'
  desc 'check', 'If /etc/shells exists, check the group ownership of each shell referenced.

Procedure:
# cat /etc/shells | xargs -n1 ls -l

Otherwise, check any shells found on the system.
Procedure:
# find / -name "*sh" | xargs -n1 ls -l

If a shell is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group-owner of the shell to root, bin, sys, or system.

Procedure:
# chgrp root <shell>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42518r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22365'
  tag rid: 'SV-45173r1_rule'
  tag stig_id: 'GEN002210'
  tag gtitle: 'GEN002210'
  tag fix_id: 'F-38571r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
