control 'SV-38731' do
  title 'All files and directories contained in user home directories must not have extended ACLs.'
  desc 'Excessive permissions allow unauthorized access to user files.'
  desc 'check', 'Check the contents of user home directories for files with extended ACLs.

Procedure:
# cat /etc/passwd | cut -f 6,6 -d ":" | xargs -n1 -IDIR aclget  DIR
OR
#aclget <directory>/<file> 

Check if extended permissions are disabled.
If extended permissions are not disabled, this is a finding.'
  desc 'fix', 'Remove the extended ACL(s) from the files and directories in user home directories and disable extended permissions.

#acledit <directory>/<file>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37154r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22352'
  tag rid: 'SV-38731r1_rule'
  tag stig_id: 'GEN001570'
  tag gtitle: 'GEN001570'
  tag fix_id: 'F-32413r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
