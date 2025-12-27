control 'SV-226569' do
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
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28730r483116_chk'
  tag severity: 'medium'
  tag gid: 'V-226569'
  tag rid: 'SV-226569r603265_rule'
  tag stig_id: 'GEN002210'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28718r483117_fix'
  tag 'documentable'
  tag legacy: ['SV-39902', 'V-22365']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
