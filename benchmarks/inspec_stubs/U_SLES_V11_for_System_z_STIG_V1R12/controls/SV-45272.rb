control 'SV-45272' do
  title 'System audit tool executables must be owned by root.'
  desc 'To prevent unauthorized access or manipulation of system audit logs, the tools for manipulating those logs must be protected.'
  desc 'check', 'Verify the audit tool executables are owned by root.
# ls -l /sbin/auditctl /sbin/auditd /sbin/ausearch /sbin/aureport /sbin/autrace /sbin/audispd 
If any listed file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the audit tool executable to root.
# chown root [audit tool executable]'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42619r1_chk'
  tag severity: 'low'
  tag gid: 'V-22370'
  tag rid: 'SV-45272r1_rule'
  tag stig_id: 'GEN002715'
  tag gtitle: 'GEN002715'
  tag fix_id: 'F-38668r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
