control 'SV-37357' do
  title 'The /etc/group file must not have an extended ACL.'
  desc 'The /etc/group file is critical to system security and must be protected from unauthorized modification.  The group file contains a list of system groups and associated information.'
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/group'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22338'
  tag rid: 'SV-37357r1_rule'
  tag stig_id: 'GEN001394'
  tag gtitle: 'GEN001394'
  tag fix_id: 'F-31291r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
