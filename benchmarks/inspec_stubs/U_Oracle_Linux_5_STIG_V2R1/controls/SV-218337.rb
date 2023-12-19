control 'SV-218337' do
  title 'All local initialization files must be owned by the home directorys user or root.'
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', "NOTE: The following commands must be run in the BASH shell.

Check the ownership of local initialization files.

Procedure:

# ls -al /<usershomedirectory>/.login
# ls -al /<usershomedirectory>/.cshrc
# ls -al /<usershomedirectory>/.logout
# ls -al /<usershomedirectory>/.profile
# ls -al /<usershomedirectory>/.bash_profile
# ls -al /<usershomedirectory>/.bashrc
# ls -al /<usershomedirectory>/.bash_logout
# ls -al /<usershomedirectory>/.env
# ls -al /<usershomedirectory>/.dtprofile
# ls -al /<usershomedirectory>/.dispatch
# ls -al /<usershomedirectory>/.emacs
# ls -al /<usershomedirectory>/.exrc
# find /<usershomedirectory>/.dt ! -fstype nfs ! -user <username> -exec ls -ld {} \\;

If local initialization files are not owned by the home directory's user, this is a finding."
  desc 'fix', %q(Change the ownership of the startup and login files in the user's directory to the user or root, as appropriate.

Examine each user's home directory and verify all filenames beginning with "." are owned by the owner of the directory or root.

If they are not, use the chown command to change the owner to the user and research the reasons why the owners were not assigned as required. 

Procedure:

# chown username .filename

Document all changes.)
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19812r568876_chk'
  tag severity: 'medium'
  tag gid: 'V-218337'
  tag rid: 'SV-218337r603259_rule'
  tag stig_id: 'GEN001860'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19810r568877_fix'
  tag 'documentable'
  tag legacy: ['V-904', 'SV-63339']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
