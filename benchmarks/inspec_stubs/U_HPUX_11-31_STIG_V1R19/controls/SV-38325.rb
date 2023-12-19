control 'SV-38325' do
  title 'All files and directories contained in user home directories must not have extended ACLs.'
  desc 'Excessive permissions allow unauthorized access to user files.'
  desc 'check', %q(Check the contents of user home directories for files with extended ACLs.
# cat /etc/passwd | cut -f 6,6 -d ":" | xargs -n1 -IDIR ls -alLR DIR

If the permissions include a '+', the file has an extended ACL, this is a finding.)
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z [user file with extended ACL]'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36361r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22352'
  tag rid: 'SV-38325r1_rule'
  tag stig_id: 'GEN001570'
  tag gtitle: 'GEN001570'
  tag fix_id: 'F-31698r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
