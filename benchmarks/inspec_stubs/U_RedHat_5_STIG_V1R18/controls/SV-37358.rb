control 'SV-37358' do
  title "The root account's home directory must not have an extended ACL."
  desc 'File system extended ACLs provide access to files beyond what is allowed by the unix permissions of the files.'
  desc 'check', "Check the root account's home directory has no extended ACL.

# find ~root -type d -prune -exec ls -ld {} \\;

If the permissions include a '+' the directory has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', "Remove the extended ACL from the root account's home directory.
# setfacl --remove-all <root home directory>"
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36046r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22309'
  tag rid: 'SV-37358r2_rule'
  tag stig_id: 'GEN000930'
  tag gtitle: 'GEN000930'
  tag fix_id: 'F-31290r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
