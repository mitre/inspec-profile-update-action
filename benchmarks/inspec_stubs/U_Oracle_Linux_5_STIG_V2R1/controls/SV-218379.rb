control 'SV-218379' do
  title 'System audit logs must have mode 0640 or less permissive.'
  desc 'If a user can write to the audit logs, audit trails can be modified or destroyed and system intrusion may not be detected.  System audit logs are those files generated from the audit system and do not include activity, error, or other log files created by application software.'
  desc 'check', 'Perform the following to determine the location of audit logs and then check the mode of the files.
Procedure:
# grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\\/]*//|xargs stat -c %a:%n

If any audit log file has a mode more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the audit log directories/files.
# chmod 0750 <audit directory>
# chmod 0640 <audit file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19854r569086_chk'
  tag severity: 'medium'
  tag gid: 'V-218379'
  tag rid: 'SV-218379r603259_rule'
  tag stig_id: 'GEN002700'
  tag gtitle: 'SRG-OS-000058-GPOS-00028'
  tag fix_id: 'F-19852r569087_fix'
  tag 'documentable'
  tag legacy: ['V-813', 'SV-63883']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
