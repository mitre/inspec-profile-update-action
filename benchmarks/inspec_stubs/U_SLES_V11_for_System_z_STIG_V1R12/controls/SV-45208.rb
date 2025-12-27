control 'SV-45208' do
  title 'System audit logs must be owned by root.'
  desc 'Failure to give ownership of system audit log files to root provides the designated owner and unauthorized users with the potential to access sensitive information.'
  desc 'check', 'Perform the following to determine the location of audit logs and then check the ownership.

Procedure:
# (audit_log_file=$(grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//) && if [ -f "${audit_log_file}" ] ; then printf "Log(s) found in "${audit_log_file%/*}":\\n"; ls -l ${audit_log_file%/*}; else printf "audit log file(s) not found\\n"; fi)

If any audit log file is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of the audit log file(s).

Procedure:
# chown root <audit log file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42556r1_chk'
  tag severity: 'medium'
  tag gid: 'V-812'
  tag rid: 'SV-45208r1_rule'
  tag stig_id: 'GEN002680'
  tag gtitle: 'GEN002680'
  tag fix_id: 'F-38604r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
