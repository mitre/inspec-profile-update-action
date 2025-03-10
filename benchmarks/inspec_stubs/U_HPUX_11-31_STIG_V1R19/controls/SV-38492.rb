control 'SV-38492' do
  title 'All local initialization files must be owned by the user or root.'
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', "Check the ownership of local initialization files.

Procedure:
# ls -alL /<usershomedirectory>/.login
# ls -alL /<usershomedirectory>/.cshrc
# ls -alL /<usershomedirectory>/.logout
# ls -alL /<usershomedirectory>/.profile
# ls -alL /<usershomedirectory>/.bash_profile
# ls -alL /<usershomedirectory>/.bashrc
# ls -alL /<usershomedirectory>/.bash_logout
# ls -alL /<usershomedirectory>/.env
# ls -alL /<usershomedirectory>/.dtprofile
# ls -alL /<usershomedirectory>/.dispatch
# ls -alL /<usershomedirectory>/.emacs
# ls -alL /<usershomedirectory>/.exrc
# find /<usershomedirectory>/.dt ! -fstype nfs ! -user <username> -exec ls -ld {} \\;

If local initialization files are not owned by the home directory's user or root, this is a finding."
  desc 'fix', %q(Change the ownership of the startup and login files in the user's directory to the user or root, as appropriate. Examine each user's home directory and verify all filenames beginning with "." are owned by the owner of the directory or root. If they are not, use the chown command to change the owner to the user and research the reasons why the owners were not assigned as required.)
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36366r2_chk'
  tag severity: 'medium'
  tag gid: 'V-904'
  tag rid: 'SV-38492r1_rule'
  tag stig_id: 'GEN001860'
  tag gtitle: 'GEN001860'
  tag fix_id: 'F-31703r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
