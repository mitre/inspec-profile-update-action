control 'SV-46273' do
  title 'All interactive user home directories must be group-owned by the home directory owners primary group.'
  desc 'If the Group Identifier (GID) of the home directory is not the same as the GID of the user, this would allow unauthorized access to files.'
  desc 'check', "Check the group ownership for each user in the /etc/passwd file.

Procedure:
# cut -d : -f 6 /etc/passwd | xargs -n1 ls -ld 

If any user home directory is not group-owned by the assigned user's primary group, this is a finding. Home directories for application accounts requiring different group ownership must be documented using site-defined procedures."
  desc 'fix', 'Change the group-owner for user home directories to the primary group of the assigned user.

Procedure:
Find the primary group of the user (GID) which is the fourth field of the user entry in /etc/passwd.

# chgrp <GID> <user home directory>

Document all changes.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-37527r2_chk'
  tag severity: 'medium'
  tag gid: 'V-903'
  tag rid: 'SV-46273r1_rule'
  tag stig_id: 'GEN001520'
  tag gtitle: 'GEN001520'
  tag fix_id: 'F-32773r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
