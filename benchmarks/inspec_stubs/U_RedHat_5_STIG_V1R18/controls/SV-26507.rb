control 'SV-26507' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-27561r1_chk'
  tag severity: 'low'
  tag gid: 'V-22371'
  tag rid: 'SV-26507r1_rule'
  tag stig_id: 'GEN002716'
  tag gtitle: 'GEN002716'
  tag fix_id: 'F-23743r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
