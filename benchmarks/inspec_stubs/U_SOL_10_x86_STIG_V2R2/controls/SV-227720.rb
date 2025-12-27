control 'SV-227720' do
  title 'System audit tool executables must be owned by root.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Verify the audit tool executables are owned by root.
# ls -l /usr/sbin/auditd /usr/sbin/audit /usr/sbin/bsmrecord /usr/sbin/auditreduce /usr/sbin/praudit /usr/sbin/auditconfig
If any listed file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the audit tool executable to root.
# chown root [audit tool executable]'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29882r488744_chk'
  tag severity: 'low'
  tag gid: 'V-227720'
  tag rid: 'SV-227720r603266_rule'
  tag stig_id: 'GEN002715'
  tag gtitle: 'SRG-OS-000256'
  tag fix_id: 'F-29870r488745_fix'
  tag 'documentable'
  tag legacy: ['V-22370', 'SV-26505']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
