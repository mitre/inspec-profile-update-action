control 'SV-38726' do
  title 'The /etc/group file must not have an extended ACL.'
  desc 'The /etc/group file is critical to system security and must be protected from unauthorized modification.  The group file contains a list of system groups and associated information.'
  desc 'check', 'Verify the /etc/group file has no extended ACL.

Procedure:

#aclget /etc/group 
Check if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the /etc/group file and disable extended permissions.

#acledit /etc/group'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37015r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22338'
  tag rid: 'SV-38726r1_rule'
  tag stig_id: 'GEN001394'
  tag gtitle: 'GEN001394'
  tag fix_id: 'F-32283r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
