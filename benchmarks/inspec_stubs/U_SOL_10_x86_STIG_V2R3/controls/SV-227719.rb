control 'SV-227719' do
  title 'All system audit files must not have extended ACLs.'
  desc 'If a user can write to the audit logs, then audit trails can be modified or destroyed and system intrusion may not be detected.'
  desc 'check', 'Check the audit configuration to determine the location of the system audit log files.
# more /etc/security/audit_control
Check the system audit log files for extended ACLs.
# ls -la [audit log dir]
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file. 
# chmod A- [audit file]'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29881r488741_chk'
  tag severity: 'medium'
  tag gid: 'V-227719'
  tag rid: 'SV-227719r603266_rule'
  tag stig_id: 'GEN002710'
  tag gtitle: 'SRG-OS-000058'
  tag fix_id: 'F-29869r488742_fix'
  tag 'documentable'
  tag legacy: ['V-22369', 'SV-26502']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
