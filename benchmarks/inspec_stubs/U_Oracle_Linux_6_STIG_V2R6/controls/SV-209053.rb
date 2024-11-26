control 'SV-209053' do
  title 'Audit log files must have mode 0640 or less permissive.'
  desc 'If users can write to audit logs, audit trails can be modified or destroyed.'
  desc 'check', 'Run the following command to check the mode of the system audit logs: 

grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %a:%n

Audit logs must be mode 0640 or less permissive. 
If any are more permissive, this is a finding.'
  desc 'fix', 'Change the mode of the audit log files with the following command: 

# chmod 0640 [audit_file]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9306r357944_chk'
  tag severity: 'medium'
  tag gid: 'V-209053'
  tag rid: 'SV-209053r793774_rule'
  tag stig_id: 'OL6-00-000383'
  tag gtitle: 'SRG-OS-000058'
  tag fix_id: 'F-9306r357945_fix'
  tag 'documentable'
  tag legacy: ['SV-64837', 'V-50631']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
