control 'SV-45211' do
  title 'All system audit files must not have extended ACLs.'
  desc 'If a user can write to the audit logs, then audit trails can be modified or destroyed and system intrusion may not be detected.'
  desc 'check', %q(Check the system audit log files for extended ACLs.

Procedure:
# grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs ls -l

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the system audit file(s).   

# setfacl --remove-all [audit file]'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42559r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22369'
  tag rid: 'SV-45211r1_rule'
  tag stig_id: 'GEN002710'
  tag gtitle: 'GEN002710'
  tag fix_id: 'F-38607r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
