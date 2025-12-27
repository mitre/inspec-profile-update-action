control 'SV-218354' do
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
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19829r569029_chk'
  tag severity: 'medium'
  tag gid: 'V-218354'
  tag rid: 'SV-218354r603259_rule'
  tag stig_id: 'GEN002210'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19827r569030_fix'
  tag 'documentable'
  tag legacy: ['V-22365', 'SV-63697']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
