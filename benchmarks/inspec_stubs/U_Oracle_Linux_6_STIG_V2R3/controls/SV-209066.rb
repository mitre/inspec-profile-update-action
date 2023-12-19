control 'SV-209066' do
  title 'Audit log files must be group-owned by root.'
  desc 'If non-privileged users can write to audit logs, audit trails can be modified or destroyed.'
  desc 'check', 'Run the following command to check the group owner of the system audit logs: 

grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %G:%n

Audit logs must be group-owned by root. 
If they are not, this is a finding.'
  desc 'fix', 'Change the group owner of the audit log files with the following command: 

# chgrp root [audit_file]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9319r357983_chk'
  tag severity: 'medium'
  tag gid: 'V-209066'
  tag rid: 'SV-209066r603263_rule'
  tag stig_id: 'OL6-00-000522'
  tag gtitle: 'SRG-OS-000057'
  tag fix_id: 'F-9319r357984_fix'
  tag 'documentable'
  tag legacy: ['V-50523', 'SV-64729']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
