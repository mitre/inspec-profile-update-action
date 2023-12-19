control 'SV-27194' do
  title 'All interactive user home directories defined in the /etc/passwd file must exist.'
  desc 'If a user has a home directory defined that does not exist, the user may be given the / directory, by default, as the current working directory upon logon.  This could create a Denial of Service because the user would not be able to perform useful tasks in this location.'
  desc 'check', "Use pwck to check that assigned home directories exist.
Procedure:
# usrck -n ALL
If any user's assigned home directory does not exist, this is a finding."
  desc 'fix', 'If a user has no home directory, determine why.  If possible, delete accounts with no home directory.  If the account is valid, then create the home directory using the appropriate system administration utility or manually create, i.e.,  mkdir <directory name>; copy the skeleton files into the directory;  chown <user name> <directory name> for the new directory and the skeleton files.  Document all changes.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28170r1_chk'
  tag severity: 'low'
  tag gid: 'V-900'
  tag rid: 'SV-27194r1_rule'
  tag stig_id: 'GEN001460'
  tag gtitle: 'GEN001460'
  tag fix_id: 'F-1054r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
