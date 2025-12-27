control 'SV-26004' do
  title 'Skeleton files must not have extended ACLs.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'check', 'Check skeleton files for extended ACLs.
# ls -alL /etc/skel
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the skeleton file(s).'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27537r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22357'
  tag rid: 'SV-26004r1_rule'
  tag stig_id: 'GEN001810'
  tag gtitle: 'GEN001810'
  tag fix_id: 'F-26200r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
