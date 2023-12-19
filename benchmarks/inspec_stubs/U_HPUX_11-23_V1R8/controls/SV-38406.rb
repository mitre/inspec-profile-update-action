control 'SV-38406' do
  title 'System audit logs must be group-owned by root, bin, sys, or other.'
  desc 'Sensitive system and user information could provide a malicious user with enough information to penetrate further into the system.'
  desc 'check', 'Inspect the auditing configuration file, /etc/rc.config.d/auditing, to determine the filename and path of the audit logs. The entries should appear similar to the following:
PRI_AUDFILE=/var/.audit/file1
SEC_AUDFILE=/var/.audit/file2

# egrep “PRI_AUDFILE|SEC_AUDFILE” /etc/rc.config.d/auditing

For each audit log directory/file, check the group ownership.
# ls -lLd <audit directory>
# ls -lLa <audit file>

If any audit log directory/file is not group-owned by root, bin, sys, or other, this is a finding.'
  desc 'fix', 'As root, change the group ownership.
# chgrp root  <audit directory>
# chgrp root  <audit file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36450r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22702'
  tag rid: 'SV-38406r2_rule'
  tag stig_id: 'GEN002690'
  tag gtitle: 'GEN002690'
  tag fix_id: 'F-31789r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1, ECTP-1'
  tag cci: ['CCI-000162', 'CCI-000163']
  tag nist: ['AU-9 a', 'AU-9 a']
end
