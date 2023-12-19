control 'SV-218383' do
  title 'System audit tool executables must have mode 0750 or less permissive.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Check the mode of audit tool executables.
# ls -l /sbin/auditctl /sbin/auditd /sbin/ausearch /sbin/aureport /sbin/autrace /sbin/audispd 
If any listed file has a mode more permissive than 0750, this is a finding.'
  desc 'fix', 'Change the mode of the audit tool executable to 0750, or less permissive.
# chmod 0750 [audit tool executable]'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19858r554486_chk'
  tag severity: 'low'
  tag gid: 'V-218383'
  tag rid: 'SV-218383r603259_rule'
  tag stig_id: 'GEN002717'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-19856r554487_fix'
  tag 'documentable'
  tag legacy: ['V-22372', 'SV-64003']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
