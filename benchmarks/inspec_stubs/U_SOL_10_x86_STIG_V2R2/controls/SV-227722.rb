control 'SV-227722' do
  title 'System audit tool executables must have mode 0750 or less permissive.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Check the mode of audit tool executables.
# ls -l /usr/sbin/auditd /usr/sbin/audit /usr/sbin/bsmrecord /usr/sbin/auditreduce /usr/sbin/praudit /usr/sbin/auditconfig
If any listed file has a mode more permissive than 0750, this is a finding.'
  desc 'fix', 'Change the mode of the audit tool executable to 0750, or less permissive.
# chmod 0750 [audit tool executable]'
  impact 0.3
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29884r488750_chk'
  tag severity: 'low'
  tag gid: 'V-227722'
  tag rid: 'SV-227722r603266_rule'
  tag stig_id: 'GEN002717'
  tag gtitle: 'SRG-OS-000256'
  tag fix_id: 'F-29872r488751_fix'
  tag 'documentable'
  tag legacy: ['V-22372', 'SV-26511']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
