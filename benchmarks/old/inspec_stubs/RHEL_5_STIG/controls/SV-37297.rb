control 'SV-37297' do
  title 'Skeleton files must not have extended ACLs.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all [skeleton file with extended ACL]
or:
# ls -lL /etc/skel|grep "\\+ "|sed "s/^.* \\//|xargs setfacl --remove-all
will remove all ACLs from the files.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22357'
  tag rid: 'SV-37297r1_rule'
  tag stig_id: 'GEN001810'
  tag gtitle: 'GEN001810'
  tag fix_id: 'F-31245r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
