control 'SV-218331' do
  title 'Skeleton files must not have extended ACLs.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'check', "Check skeleton files for extended ACLs:

# ls -alL /etc/skel

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all [skeleton file with extended ACL]
or:
# ls -lL /etc/skel|grep "\\+ "|sed "s/^.* \\//|xargs setfacl --remove-all
will remove all ACLs from the files.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19806r561743_chk'
  tag severity: 'medium'
  tag gid: 'V-218331'
  tag rid: 'SV-218331r603259_rule'
  tag stig_id: 'GEN001810'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19804r561744_fix'
  tag 'documentable'
  tag legacy: ['V-22357', 'SV-63881']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
