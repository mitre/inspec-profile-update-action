control 'SV-38346' do
  title 'Skeleton files must not have extended ACLs.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'check', 'Check skeleton files for extended ACLs.
# ls -alL /etc/skel

If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z [skeleton file with extended ACL]'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36385r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22357'
  tag rid: 'SV-38346r1_rule'
  tag stig_id: 'GEN001810'
  tag gtitle: 'GEN001810'
  tag fix_id: 'F-31724r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
