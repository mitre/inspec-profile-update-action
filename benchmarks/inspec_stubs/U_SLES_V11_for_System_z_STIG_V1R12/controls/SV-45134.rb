control 'SV-45134' do
  title 'Skeleton files must not have extended ACLs.'
  desc 'If the skeleton files are not protected, unauthorized personnel could change user startup parameters and possibly jeopardize user files.'
  desc 'check', "Check skeleton files for extended ACLs:
# ls -alL /etc/skel.
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all [skeleton file with extended ACL]
or:
# ls -lL /etc/skel|grep "\\+ "|awk ‘{print “/etc/skel/”$9}’|xargs setfacl --remove-all
will remove all ACLs from the files.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42479r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22357'
  tag rid: 'SV-45134r1_rule'
  tag stig_id: 'GEN001810'
  tag gtitle: 'GEN001810'
  tag fix_id: 'F-38530r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
