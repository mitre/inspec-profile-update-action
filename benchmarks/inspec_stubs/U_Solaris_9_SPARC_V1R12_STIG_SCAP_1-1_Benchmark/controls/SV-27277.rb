control 'SV-27277' do
  title 'System audit logs must be group-owned by root, bin, or sys.'
  desc 'Sensitive system and user information could provide a malicious user with enough information to penetrate further into the system.'
  desc 'fix', 'Change the group ownership of the audit log file(s).

Procedure:
# chgrp root <audit log file>'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22702'
  tag rid: 'SV-27277r1_rule'
  tag stig_id: 'GEN002690'
  tag gtitle: 'GEN002690'
  tag fix_id: 'F-24520r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1, ECTP-1'
  tag cci: ['CCI-000162', 'CCI-000163']
  tag nist: ['AU-9 a', 'AU-9 a']
end
