control 'SV-226527' do
  title 'All interactive user home directories defined in the /etc/passwd file must exist.'
  desc 'If a user has a home directory defined that does not exist, the user may be given the / directory, by default, as the current working directory upon logon.  This could create a Denial of Service because the user would not be able to perform useful tasks in this location.'
  desc 'check', "Use pwck to verify assigned home directories exist.
# pwck
If any user's assigned home directory does not exist, this is a finding."
  desc 'fix', "If a user has no home directory, determine why. If possible, delete accounts that have no home directory. If the account is valid, then create the home directory using the appropriate system administration utility or manually.

For instance: mkdir directoryname; copy the skeleton files into the directory; chown accountname for the new directory and the skeleton files. Document all changes.   

Update the sixth field in the /etc/passwd file to reflect the user's home directory.  
# usermod -d
OR
# vi /etc/passwd"
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36385r602758_chk'
  tag severity: 'low'
  tag gid: 'V-226527'
  tag rid: 'SV-226527r603265_rule'
  tag stig_id: 'GEN001460'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36349r602759_fix'
  tag 'documentable'
  tag legacy: ['SV-27192', 'V-900']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
