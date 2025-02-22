control 'SV-27192' do
  title 'All interactive user home directories defined in the /etc/passwd file must exist.'
  desc 'If a user has a home directory defined that does not exist, the user may be given the / directory, by default, as the current working directory upon logon.  This could create a Denial of Service because the user would not be able to perform useful tasks in this location.'
  desc 'fix', "If a user has no home directory, determine why. If possible, delete accounts that have no home directory. If the account is valid, then create the home directory using the appropriate system administration utility or manually.

For instance: mkdir directoryname; copy the skeleton files into the directory; chown accountname for the new directory and the skeleton files. Document all changes.   

Update the sixth field in the /etc/passwd file to reflect the user's home directory.  
# usermod -d
OR
# vi /etc/passwd"
  impact 0.3
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'low'
  tag gid: 'V-900'
  tag rid: 'SV-27192r1_rule'
  tag stig_id: 'GEN001460'
  tag gtitle: 'GEN001460'
  tag fix_id: 'F-33976r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
