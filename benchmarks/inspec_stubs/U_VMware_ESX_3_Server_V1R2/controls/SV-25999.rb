control 'SV-25999' do
  title 'All files and directories contained in user home directories must not have extended ACLs.'
  desc 'Excessive permissions allow unauthorized access to user files.'
  desc 'check', %q(Check the contents of user's home directories for files with extended ACLs.
# cut -d : -f 6 /etc/passwd | xargs -n1 -IDIR ls -alLR DIR
If the permissions include a "+", the file has an extended ACL, this is a finding.)
  desc 'fix', 'Remove the extended ACL(s) from the files and directories in user home directories.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27523r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22352'
  tag rid: 'SV-25999r1_rule'
  tag stig_id: 'GEN001570'
  tag gtitle: 'GEN001570'
  tag fix_id: 'F-26195r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
