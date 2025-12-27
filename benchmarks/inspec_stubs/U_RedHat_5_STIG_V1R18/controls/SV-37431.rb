control 'SV-37431' do
  title 'All local initialization files must have mode 0740 or less permissive.'
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Check the modes of local initialization files.

Procedure:
# ls -al /<usershomedirectory>/.bashrc
# ls -al /<usershomedirectory>/.bash_login
# ls -al /<usershomedirectory>/.bash_logout
# ls -al /<usershomedirectory>/.bash_profile
# ls -al /<usershomedirectory>/.cshrc
# ls -al /<usershomedirectory>/.kshrc
# ls -al /<usershomedirectory>/.login
# ls -al /<usershomedirectory>/.logout
# ls -al /<usershomedirectory>/.profile
# ls -al /<usershomedirectory>/.tcshrc
# ls -al /<usershomedirectory>/.env
# ls -al /<usershomedirectory>/.dtprofile (permissions should be 0755)
# ls -al /<usershomedirectory>/.dispatch
# ls -al /<usershomedirectory>/.emacs
# ls -al /<usershomedirectory>/.exrc
# find /<usershomedirectory>/.dt ! -fstype nfs \\( -perm -0002 -o -perm -0020 \\) -exec ls -ld {} \\; (permissions not to be more
permissive than 0755)

If local initialization files are more permissive than 0740 or the .dt directory is more permissive than 0755 or the .dtprofile file is more permissive than 0755, this is a finding.'
  desc 'fix', %q(Ensure user startup files have permissions of 0740 or more restrictive. Examine each user's home directory and verify all file names beginning with "." have access permissions of 0740 or more restrictive. If they do not, use the chmod command to correct the vulnerability. 

Procedure: 
# chmod 0740 .filename 

Note: The period is part of the file name and is required.)
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36108r1_chk'
  tag severity: 'medium'
  tag gid: 'V-905'
  tag rid: 'SV-37431r1_rule'
  tag stig_id: 'GEN001880'
  tag gtitle: 'GEN001880'
  tag fix_id: 'F-31202r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
