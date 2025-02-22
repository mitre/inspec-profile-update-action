control 'SV-25956' do
  title "The root account's home directory must not have an extended ACL."
  desc 'File system extended ACLs provide access to files beyond what is allowed by the mode numbers of the files.'
  desc 'check', %q(Verify the root account's home directory has no extended ACL.
# ls -ld ~root
If the permissions include a "+", the directory has an extended ACL and this is a finding.)
  desc 'fix', "Remove the extended ACL from the root account's home directory."
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27457r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22309'
  tag rid: 'SV-25956r1_rule'
  tag stig_id: 'GEN000930'
  tag gtitle: 'GEN000930'
  tag fix_id: 'F-26097r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
