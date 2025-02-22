control 'SV-220083' do
  title "All interactive user's home directories must be group-owned by the home directory owner's primary group."
  desc 'If the GID of the home directory is not the same as the GID of the user, this would allow unauthorized access to files.'
  desc 'check', "Check the group ownership for each user in the /etc/passwd file. 

Procedure: 
# cut -d : -f 6 /etc/passwd | xargs -n1 ls -ld | more

If any user's home directory is not group-owned by the assigned user's primary group, this is a finding. Home directories for application accounts requiring different group ownership must be documented using site-defined procedures."
  desc 'fix', "Change the group owner for user's home directories to the primary group of the assigned user.

Procedure:
# chgrp groupname directoryname

(Replace examples with appropriate group and home directory.)

Document all changes."
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21792r488537_chk'
  tag severity: 'medium'
  tag gid: 'V-220083'
  tag rid: 'SV-220083r603266_rule'
  tag stig_id: 'GEN001520'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21791r488538_fix'
  tag 'documentable'
  tag legacy: ['V-903', 'SV-39823']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
