control 'SV-218101' do
  title 'Audit log files must be group-owned by root.'
  desc 'If non-privileged users can write to audit logs, audit trails can be modified or destroyed.'
  desc 'check', 'Run the following command to check the group owner of the system audit logs: 

grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %G:%n

Audit logs must be group-owned by root. 
If they are not, this is a finding.'
  desc 'fix', 'Change the group owner of the audit log files with the following command: 

# chgrp root [audit_file]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19582r377318_chk'
  tag severity: 'medium'
  tag gid: 'V-218101'
  tag rid: 'SV-218101r603264_rule'
  tag stig_id: 'RHEL-06-000522'
  tag gtitle: 'SRG-OS-000057'
  tag fix_id: 'F-19580r377319_fix'
  tag 'documentable'
  tag legacy: ['SV-50245', 'V-38445']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
