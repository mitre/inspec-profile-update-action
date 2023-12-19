control 'SV-218382' do
  title 'System audit tool executables must be group-owned by root, bin, sys, or system.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Verify the audit tool executables are group-owned by root, bin, sys, or system.

Procedure:
# ls -lL /sbin/auditctl /sbin/auditd /sbin/ausearch /sbin/aureport /sbin/autrace /sbin/audispd 

If any listed file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group-owner of the audit tool executable to root, bin, sys, or system.

Procedure:
# chgrp root <audit tool executable>'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19857r554483_chk'
  tag severity: 'low'
  tag gid: 'V-218382'
  tag rid: 'SV-218382r603259_rule'
  tag stig_id: 'GEN002716'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-19855r554484_fix'
  tag 'documentable'
  tag legacy: ['V-22371', 'SV-63975']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
