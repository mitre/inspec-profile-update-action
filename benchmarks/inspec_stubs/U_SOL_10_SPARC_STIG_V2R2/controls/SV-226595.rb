control 'SV-226595' do
  title 'System audit tool executables must be group-owned by root, bin, or sys.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Verify the audit tool executables are group-owned by root, bin, or sys.

Procedure:
# ls -lL /usr/sbin/auditd /usr/sbin/audit /usr/sbin/bsmrecord /usr/sbin/auditreduce /usr/sbin/praudit /usr/sbin/auditconfig

If any listed file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group-owner of the audit tool executable to root, bin, or sys.

Procedure:
# chgrp root <audit tool executable>'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28756r483197_chk'
  tag severity: 'low'
  tag gid: 'V-226595'
  tag rid: 'SV-226595r603265_rule'
  tag stig_id: 'GEN002716'
  tag gtitle: 'SRG-OS-000256'
  tag fix_id: 'F-28744r483198_fix'
  tag 'documentable'
  tag legacy: ['V-22371', 'SV-26508']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
