control 'SV-218084' do
  title 'Audit log files must have mode 0640 or less permissive.'
  desc 'If users can write to audit logs, audit trails can be modified or destroyed.'
  desc 'check', 'Run the following command to check the mode of the system audit logs: 

grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %a:%n

Audit logs must be mode 0640 or less permissive. 
If any are more permissive, this is a finding.'
  desc 'fix', 'Change the mode of the audit log files with the following command: 

# chmod 0640 [audit_file]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19565r377267_chk'
  tag severity: 'medium'
  tag gid: 'V-218084'
  tag rid: 'SV-218084r603264_rule'
  tag stig_id: 'RHEL-06-000383'
  tag gtitle: 'SRG-OS-000058'
  tag fix_id: 'F-19563r377268_fix'
  tag 'documentable'
  tag legacy: ['SV-50299', 'V-38498']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
