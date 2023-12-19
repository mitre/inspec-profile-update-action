control 'SV-38322' do
  title 'The /etc/group file must not have an extended ACL.'
  desc 'The /etc/group file is critical to system security and must be protected from unauthorized modification.  The group file contains a list of system groups and associated information.'
  desc 'check', 'Verify /etc/group has no extended ACL.
# ls -lL /etc/group

If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /etc/group file.
# chacl -z /etc/group'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36355r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22338'
  tag rid: 'SV-38322r1_rule'
  tag stig_id: 'GEN001394'
  tag gtitle: 'GEN001394'
  tag fix_id: 'F-31654r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
