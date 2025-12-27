control 'SV-209054' do
  title 'Audit log files must be owned by root.'
  desc 'If non-privileged users can write to audit logs, audit trails can be modified or destroyed.'
  desc 'check', 'Run the following command to check the owner of the system audit logs: 

grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %U:%n

Audit logs must be owned by root. 
If they are not, this is a finding.'
  desc 'fix', 'Change the owner of the audit log files with the following command: 

# chown root [audit_file]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9307r357947_chk'
  tag severity: 'medium'
  tag gid: 'V-209054'
  tag rid: 'SV-209054r603263_rule'
  tag stig_id: 'OL6-00-000384'
  tag gtitle: 'SRG-OS-000057'
  tag fix_id: 'F-9307r357948_fix'
  tag 'documentable'
  tag legacy: ['SV-64835', 'V-50629']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
