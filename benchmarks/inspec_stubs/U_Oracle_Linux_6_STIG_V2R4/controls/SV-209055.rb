control 'SV-209055' do
  title 'Audit log directories must have mode 0755 or less permissive.'
  desc 'If users can delete audit logs, audit trails can be modified or destroyed.'
  desc 'check', %q(Run the following command to check the mode of the system audit directories: 

grep "^log_file" /etc/audit/auditd.conf|sed 's/^[^/]*//; s/[^/]*$//'|xargs stat -c %a:%n

Audit directories must be mode 0755 or less permissive. 
If any are more permissive, this is a finding.)
  desc 'fix', 'Change the mode of the audit log directories with the following command: 

# chmod go-w [audit_directory]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9308r357950_chk'
  tag severity: 'medium'
  tag gid: 'V-209055'
  tag rid: 'SV-209055r603263_rule'
  tag stig_id: 'OL6-00-000385'
  tag gtitle: 'SRG-OS-000059'
  tag fix_id: 'F-9308r357951_fix'
  tag 'documentable'
  tag legacy: ['SV-64833', 'V-50627']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
