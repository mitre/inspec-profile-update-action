control 'SV-38478' do
  title 'System audit logs must have mode 0640 or less permissive.'
  desc 'If a user can write to the audit logs, audit trails can be modified or destroyed and system intrusion may not be detected.  System audit logs are those files generated from the audit system and do not include activity, error, or other log files created by application software.'
  desc 'check', 'Inspect the auditing configuration file, /etc/rc.config.d/auditing, to determine the filename and path of the audit logs. The entries should appear similar to the following:
PRI_AUDFILE=/var/.audit/file1
SEC_AUDFILE=/var/.audit/file2

# egrep “PRI_AUDFILE|SEC_AUDFILE” /etc/rc.config.d/auditing

For each audit log directory/file, check the permissions.
# ls -lLd <audit directory>
# ls -lLa <audit file>

If any audit log file has permissions greater than 0640 (0750 for directories), this is a finding.'
  desc 'fix', 'As root, change the permissions.
# chmod 0750  <audit directory>
# chmod 0640  <audit file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36425r2_chk'
  tag severity: 'medium'
  tag gid: 'V-813'
  tag rid: 'SV-38478r2_rule'
  tag stig_id: 'GEN002700'
  tag gtitle: 'GEN002700'
  tag fix_id: 'F-31764r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECTP-1'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
