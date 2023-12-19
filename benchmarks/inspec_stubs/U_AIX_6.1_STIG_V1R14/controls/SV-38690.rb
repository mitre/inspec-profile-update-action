control 'SV-38690' do
  title "The root account's home directory must not have an extended ACL."
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.'
  desc 'check', "Verify the root account's home directory has no extended ACL.

Procedure:
# aclget ~root
If extended permissions are enabled,  the directory has an extended ACL, and this is a finding."
  desc 'fix', "Remove the extended ACL from the root account's home directory.
#acledit ~root 
Change extended attributes to disabled."
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36915r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22309'
  tag rid: 'SV-38690r1_rule'
  tag stig_id: 'GEN000930'
  tag gtitle: 'GEN000930'
  tag fix_id: 'F-32136r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
