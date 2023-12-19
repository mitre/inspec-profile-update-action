control 'SV-904' do
  title 'All local initialization files must be owned by the user or root.'
  desc "Local initialization files are used to configure the user's shell environment upon login.  Malicious modification of these files could compromise accounts upon logon."
  desc 'check', %q(NOTE: The following commands must be run in the BASH shell.

Check the ownership of local initialization files.

Procedure (using a shell that supports ~USER as USER's home directory):
# cut -d : -f 1 /etc/passwd | xargs -n1 -IUSER sh -c "ls -l ~USER/.[a-z]*"
# cut -d : -f 1 /etc/passwd | xargs -n1 -IUSER find ~USER/.dt ! -fstype nfs ! -user USER -exec ls -ld {} \;

If local initialization files are not owned by the home directory's user, this is a finding.)
  desc 'fix', %q(Change the ownership of the startup and login files in the user's directory to the user or root, as appropriate.  Examine each user's home directory and verify all file names beginning with "." are owned by the owner of the directory or root.  If they are not, use the chown command to change the owner to the user and research the reasons why the owners were not assigned as required.  

Procedure:
# chown username .filename
Document all changes.)
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-395r4_chk'
  tag severity: 'medium'
  tag gid: 'V-904'
  tag rid: 'SV-904r3_rule'
  tag stig_id: 'GEN001860'
  tag gtitle: 'GEN001860'
  tag fix_id: 'F-1058r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
