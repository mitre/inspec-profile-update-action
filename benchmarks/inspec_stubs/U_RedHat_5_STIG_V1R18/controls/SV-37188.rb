control 'SV-37188' do
  title 'All files and directories contained in user home directories must not have extended ACLs.'
  desc 'Excessive permissions allow unauthorized access to user files.'
  desc 'check', "Check the contents of user home directories for files with extended ACLs.
# cut -d : -f 6 /etc/passwd | xargs -n1 -IDIR ls -alLR DIR
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all <user file with extended ACL>'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37530r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22352'
  tag rid: 'SV-37188r1_rule'
  tag stig_id: 'GEN001570'
  tag gtitle: 'GEN001570'
  tag fix_id: 'F-32776r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
