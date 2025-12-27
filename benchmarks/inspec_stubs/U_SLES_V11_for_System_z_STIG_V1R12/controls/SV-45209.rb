control 'SV-45209' do
  title 'System audit logs must be group-owned by root, bin, sys, or system.'
  desc 'Sensitive system and user information could provide a malicious user with enough information to penetrate further into the system.'
  desc 'check', 'Check the group ownership of the audit logs.

Procedure:
# (audit_log_file=$(grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//) && if [ -f "${audit_log_file}" ] ; then printf "Log(s) found in "${audit_log_file%/*}":\\n"; ls -l ${audit_log_file%/*}; else printf "audit log file(s) not found\\n"; fi)
If any audit log file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group-ownership of the audit log file(s).

Procedure:
# chgrp root <audit log file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42557r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22702'
  tag rid: 'SV-45209r1_rule'
  tag stig_id: 'GEN002690'
  tag gtitle: 'GEN002690'
  tag fix_id: 'F-38605r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000162', 'CCI-000163']
  tag nist: ['AU-9 a', 'AU-9 a']
end
