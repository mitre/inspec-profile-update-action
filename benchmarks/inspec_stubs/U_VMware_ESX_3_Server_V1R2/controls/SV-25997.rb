control 'SV-25997' do
  title 'User home directories must not have extended ACLs.'
  desc 'Excessive permissions on home directories allow unauthorized access to user files.'
  desc 'check', %q(Verify user's home directories have no extended ACLs.

# cut -d : -f 6 /etc/passwd | xargs -n1 ls -ld 

If the permissions include a "+", the file has an extended ACL, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the user home directory.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27521r1_chk'
  tag severity: 'low'
  tag gid: 'V-22350'
  tag rid: 'SV-25997r1_rule'
  tag stig_id: 'GEN001490'
  tag gtitle: 'GEN001490'
  tag fix_id: 'F-26194r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
