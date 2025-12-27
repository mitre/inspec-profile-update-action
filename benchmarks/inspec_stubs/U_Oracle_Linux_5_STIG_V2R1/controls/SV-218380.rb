control 'SV-218380' do
  title 'All system audit files must not have extended ACLs.'
  desc 'If a user can write to the audit logs, then audit trails can be modified or destroyed and system intrusion may not be detected.'
  desc 'check', %q(Check the system audit log files for extended ACLs.

Procedure:
# grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs ls -l

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the system audit file(s).'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19855r554477_chk'
  tag severity: 'medium'
  tag gid: 'V-218380'
  tag rid: 'SV-218380r603259_rule'
  tag stig_id: 'GEN002710'
  tag gtitle: 'SRG-OS-000058-GPOS-00028'
  tag fix_id: 'F-19853r554478_fix'
  tag 'documentable'
  tag legacy: ['V-22369', 'SV-63885']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
