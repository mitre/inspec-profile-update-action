control 'SV-38902' do
  title 'System audit logs must be group-owned by bin, sys, or system.'
  desc 'Sensitive system and user information could provide a malicious user with enough information to penetrate further into the system.'
  desc 'check', 'Procedure:
# grep -p bin: /etc/security/audit/config
Directories to search will be listed under the bin stanza.

# ls -la <audit directories>

If any audit log file is not group-owned by bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group ownership of the audit log file(s). Procedure:

# chgrp system < audit log file >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37246r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22702'
  tag rid: 'SV-38902r1_rule'
  tag stig_id: 'GEN002690'
  tag gtitle: 'GEN002690'
  tag fix_id: 'F-33355r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1, ECTP-1'
  tag cci: ['CCI-000162', 'CCI-000163']
  tag nist: ['AU-9 a', 'AU-9 a']
end
