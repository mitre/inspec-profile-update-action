control 'SV-45277' do
  title 'System audit tool executables must have mode 0750 or less permissive.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Check the mode of audit tool executables.
# ls -l /sbin/auditctl /sbin/auditd /sbin/ausearch /sbin/aureport /sbin/autrace /sbin/audispd 
If any listed file has a mode more permissive than 0750, this is a finding.'
  desc 'fix', 'Change the mode of the audit tool executable to 0750, or less permissive.
# chmod 0750 [audit tool executable]'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42624r1_chk'
  tag severity: 'low'
  tag gid: 'V-22372'
  tag rid: 'SV-45277r1_rule'
  tag stig_id: 'GEN002717'
  tag gtitle: 'GEN002717'
  tag fix_id: 'F-38673r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
