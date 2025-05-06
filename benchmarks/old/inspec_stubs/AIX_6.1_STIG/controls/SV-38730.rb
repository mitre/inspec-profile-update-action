control 'SV-38730' do
  title 'User home directories must not have extended ACLs.'
  desc 'Excessive permissions on home directories allow unauthorized access to user files.'
  desc 'check', 'Verify user home directories have no extended ACLs.

Procedure:
# cat /etc/passwd | cut -f 6,6 -d ":" | xargs -n1 aclget

Check if extended permissions are disabled.
If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the user home directory and disable extended permissions.
   
#acledit <directory>/<file>'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37152r1_chk'
  tag severity: 'low'
  tag gid: 'V-22350'
  tag rid: 'SV-38730r1_rule'
  tag stig_id: 'GEN001490'
  tag gtitle: 'GEN001490'
  tag fix_id: 'F-32412r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
