control 'SV-226591' do
  title 'System audit logs must be group-owned by root, bin, or sys.'
  desc 'Sensitive system and user information could provide a malicious user with enough information to penetrate further into the system.'
  desc 'check', 'Determine the location of audit logs and then check the group-ownership.

Procedure:
# more /etc/security/audit_control
# ls -lLd <audit log dir>

If any audit log file is not group-owned by root, bin, or sys, this is a finding.'
  desc 'fix', 'Change the group ownership of the audit log file(s).

Procedure:
# chgrp root <audit log file>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28752r483185_chk'
  tag severity: 'medium'
  tag gid: 'V-226591'
  tag rid: 'SV-226591r603265_rule'
  tag stig_id: 'GEN002690'
  tag gtitle: 'SRG-OS-000057'
  tag fix_id: 'F-28740r483186_fix'
  tag 'documentable'
  tag legacy: ['V-22702', 'SV-27277']
  tag cci: ['CCI-000162', 'CCI-000163']
  tag nist: ['AU-9 a', 'AU-9 a']
end
