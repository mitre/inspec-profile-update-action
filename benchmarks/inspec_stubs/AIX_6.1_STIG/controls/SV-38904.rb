control 'SV-38904' do
  title 'System audit logs must have mode 0640 or less permissive.'
  desc 'If a user can write to the audit logs, audit trails can be modified or destroyed and system intrusion may not be detected.  System audit logs are those files generated from the audit system and do not include activity, error, or other log files created by application software.'
  desc 'check', 'Perform the following to determine the location of audit logs and then check the mode of the files.
Procedure:
# grep -p bin: /etc/security/audit/config
Directories to search will be listed under the bin stanza.
# ls -la <audit directories>
If any audit log file has a mode more permissive than 0640, this is a finding.'
  desc 'fix', 'Change the mode of the audit log directories/files.
# chmod 0750 <audit directory>
# chmod 0640 <audit file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37247r1_chk'
  tag severity: 'medium'
  tag gid: 'V-813'
  tag rid: 'SV-38904r1_rule'
  tag stig_id: 'GEN002700'
  tag gtitle: 'GEN002700'
  tag fix_id: 'F-967r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECTP-1'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
