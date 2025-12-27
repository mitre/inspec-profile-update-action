control 'SV-903' do
  title "All interactive users' home directories must be group-owned by the home directory owner's primary group."
  desc 'If the GID of the home directory is not the same as the GID of the user, this would allow unauthorized access to files.'
  desc 'check', "Check the group ownership for each user in the /etc/passwd file.

Procedure:
# ls -lLd <user home directory>

If any user's home directory is not group-owned by the assigned user's primary group, this is a finding. Home directories for application accounts requiring different group ownership must be documented using site-defined procedures."
  desc 'fix', "Change the group owner for user's home directories to the primary group of the assigned user.

Procedure:
# chgrp groupname directoryname

(Replace examples with appropriate group and home directory.)

Document all changes."
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-8019r3_chk'
  tag severity: 'medium'
  tag gid: 'V-903'
  tag rid: 'SV-903r2_rule'
  tag stig_id: 'GEN001520'
  tag gtitle: 'GEN001520'
  tag fix_id: 'F-1057r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
