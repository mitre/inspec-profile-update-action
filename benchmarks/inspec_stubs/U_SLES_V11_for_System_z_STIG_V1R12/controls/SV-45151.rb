control 'SV-45151' do
  title 'All local initialization files must be owned by the home directorys user or root.'
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', %q(Check the ownership of local initialization files.

Procedure:
# ls –a /<users home directory> | grep “^\.” | awk '{if ((!($1=="."))&&(!($1==".."))) print}' | xargs ls -ld

If local initialization files are not owned by the home directory's user, this is a finding.)
  desc 'fix', 'Change the ownership of the startup and login files in the user’s directory to the user or root, as appropriate. Examine each user’s home directory and verify all filenames beginning with “.” are owned by the owner of the directory or root. If they are not, use the chown command to change the owner to the user and research the reasons why the owners were not assigned as required. 

Procedure:
# chown username .filename
Document all changes.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42494r1_chk'
  tag severity: 'medium'
  tag gid: 'V-904'
  tag rid: 'SV-45151r1_rule'
  tag stig_id: 'GEN001860'
  tag gtitle: 'GEN001860'
  tag fix_id: 'F-38547r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
