control 'SV-29692' do
  title 'System files are not checked for unauthorized changes.'
  desc 'Comparing system files against a baseline on a regular basis will detect  the possibility of introduction of malicious code on the system.'
  desc 'check', 'Interview the SA to determine if the site uses a tool to compare system files (*.exe, *.bat, *.com, *.cmd and *.dll) on servers against a baseline, on a weekly basis.

Note: A properly configured HBSS Policy Auditor 5.2 or later, File Integrity Monitor (FIM) module will meet the requirement for file integrity checking.  The Asset module within HBSS does not meet this requirement.'
  desc 'fix', 'The site should use a tool to compare system files (*.exe, *.bat, *.com, *.cmd and *.dll) on servers against a baseline, on a weekly basis.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-7891r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2907'
  tag rid: 'SV-29692r1_rule'
  tag gtitle: 'System File Changes'
  tag fix_id: 'F-42r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
