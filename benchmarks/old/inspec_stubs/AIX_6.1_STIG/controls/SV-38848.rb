control 'SV-38848' do
  title 'All shell files must be group-owned by root, bin, sys, or system.'
  desc 'If shell files are group-owned by users other than root or a system group, they could be modified by intruders or malicious users to perform unauthorized actions.'
  desc 'check', 'Check the group ownership of each shell referenced.

Procedure:
# cat /etc/shells | xargs -n1 ls -l
If any shell is not group owned by root, bin, sys, or system, this is a finding.

#grep shells /etc/security/login.cfg | grep -v \\* | cut -f 2 -d = | sed s/,/\\ /g | xargs -n1 ls -l
If any shell is not group owned by root, bin, sys, or system, this is a finding.

Otherwise, check any shells found on the system.
Procedure:
# find / -name "*sh" | xargs -n1 ls -l

If a shell is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the shell to root, bin, sys, or system.

# chgrp system < shell >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37180r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22365'
  tag rid: 'SV-38848r1_rule'
  tag stig_id: 'GEN002210'
  tag gtitle: 'GEN002210'
  tag fix_id: 'F-33104r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
