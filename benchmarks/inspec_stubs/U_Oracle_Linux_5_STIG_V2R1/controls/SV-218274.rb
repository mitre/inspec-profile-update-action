control 'SV-218274' do
  title 'All library files must not have extended ACLs.'
  desc 'Unauthorized access could destroy the integrity of the library files.'
  desc 'check', %q(Verify system libraries have no extended ACLs.

# ls -lLR /usr/lib/ /lib/ /usr/lib64 /lib64 | grep "+ "

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and has not been approved by the IAO, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /usr/lib/* /lib/*'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19749r554159_chk'
  tag severity: 'medium'
  tag gid: 'V-218274'
  tag rid: 'SV-218274r603259_rule'
  tag stig_id: 'GEN001310'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19747r554160_fix'
  tag 'documentable'
  tag legacy: ['V-22317', 'SV-64531']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
