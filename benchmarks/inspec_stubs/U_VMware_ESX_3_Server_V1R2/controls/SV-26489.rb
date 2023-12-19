control 'SV-26489' do
  title 'All shell files must be group-owned by root, bin, sys, or system.'
  desc 'If shell files are group-owned by users other than root or a system group, they could be modified by intruders or malicious users to perform unauthorized actions.'
  desc 'check', 'If /etc/shells exists, check the group ownership of each shell referenced.

Procedure:
# cat /etc/shells | xargs -n1 ls -lL

Otherwise, check any shells found on the system.
Procedure:
# find / -name "*sh" | xargs -n1 ls -lL

If a shell is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group-owner of the shell to root, bin, sys, or system.

Procedure:
# chgrp root <shell>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27548r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22365'
  tag rid: 'SV-26489r1_rule'
  tag stig_id: 'GEN002210'
  tag gtitle: 'GEN002210'
  tag fix_id: 'F-23718r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
