control 'SV-38324' do
  title 'User home directories must not have extended ACLs.'
  desc 'Excessive permissions on home directories allow unauthorized access to user files.'
  desc 'check', 'Verify user home directories have no extended ACLs.
# cat /etc/passwd | cut -f 6,6 -d ":" | xargs -n1 ls -lLd 

If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z [user home directory with extended ACL]'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36360r1_chk'
  tag severity: 'low'
  tag gid: 'V-22350'
  tag rid: 'SV-38324r1_rule'
  tag stig_id: 'GEN001490'
  tag gtitle: 'GEN001490'
  tag fix_id: 'F-31697r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
