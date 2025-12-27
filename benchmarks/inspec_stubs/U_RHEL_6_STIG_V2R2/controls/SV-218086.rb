control 'SV-218086' do
  title 'Audit log directories must have mode 0755 or less permissive.'
  desc 'If users can delete audit logs, audit trails can be modified or destroyed.'
  desc 'check', %q(Run the following command to check the mode of the system audit directories: 

grep "^log_file" /etc/audit/auditd.conf|sed 's/^[^/]*//; s/[^/]*$//'|xargs stat -c %a:%n

Audit directories must be mode 0755 or less permissive. 
If any are more permissive, this is a finding.)
  desc 'fix', 'Change the mode of the audit log directories with the following command: 

# chmod go-w [audit_directory]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19567r377273_chk'
  tag severity: 'medium'
  tag gid: 'V-218086'
  tag rid: 'SV-218086r603264_rule'
  tag stig_id: 'RHEL-06-000385'
  tag gtitle: 'SRG-OS-000059'
  tag fix_id: 'F-19565r377274_fix'
  tag 'documentable'
  tag legacy: ['SV-50294', 'V-38493']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
