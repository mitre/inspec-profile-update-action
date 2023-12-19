control 'SV-218085' do
  title 'Audit log files must be owned by root.'
  desc 'If non-privileged users can write to audit logs, audit trails can be modified or destroyed.'
  desc 'check', 'Run the following command to check the owner of the system audit logs: 

grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %U:%n

Audit logs must be owned by root. 
If they are not, this is a finding.'
  desc 'fix', 'Change the owner of the audit log files with the following command: 

# chown root [audit_file]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19566r377270_chk'
  tag severity: 'medium'
  tag gid: 'V-218085'
  tag rid: 'SV-218085r603264_rule'
  tag stig_id: 'RHEL-06-000384'
  tag gtitle: 'SRG-OS-000057'
  tag fix_id: 'F-19564r377271_fix'
  tag 'documentable'
  tag legacy: ['SV-50296', 'V-38495']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
