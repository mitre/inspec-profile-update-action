control 'SV-218381' do
  title 'System audit tool executables must be owned by root.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Verify the audit tool executables are owned by root.
# ls -l /sbin/auditctl /sbin/auditd /sbin/ausearch /sbin/aureport /sbin/autrace /sbin/audispd 
If any listed file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the audit tool executable to root.
# chown root [audit tool executable]'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19856r554480_chk'
  tag severity: 'low'
  tag gid: 'V-218381'
  tag rid: 'SV-218381r603259_rule'
  tag stig_id: 'GEN002715'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag fix_id: 'F-19854r554481_fix'
  tag 'documentable'
  tag legacy: ['V-22370', 'SV-63959']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
