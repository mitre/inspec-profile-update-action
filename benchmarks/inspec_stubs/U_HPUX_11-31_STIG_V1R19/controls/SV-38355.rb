control 'SV-38355' do
  title 'All system audit files must not have extended ACLs.'
  desc 'If a user can write to the audit logs, then audit trails can be modified or destroyed and system intrusion may not be detected.'
  desc 'check', 'Inspect the auditing configuration file, /etc/rc.config.d/auditing, to determine the filename and path of the audit logs. The entries should appear similar to the following:
PRI_AUDFILE=/var/.audit/file1
SEC_AUDFILE=/var/.audit/file2

# egrep “PRI_AUDFILE|SEC_AUDFILE” /etc/rc.config.d/auditing

For each audit log directory/file, check the permissions.
# ls -lLd <audit directory>
# ls -lLa <audit file>

If any audit log directory/file permissions include a “+”, this is a finding.'
  desc 'fix', 'As root, remove the ACL.
# chacl -z  <audit directory>
# chacl -z  <audit file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36436r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22369'
  tag rid: 'SV-38355r2_rule'
  tag stig_id: 'GEN002710'
  tag gtitle: 'GEN002710'
  tag fix_id: 'F-31775r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECTP-1'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
