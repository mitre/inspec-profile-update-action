control 'SV-218305' do
  title 'All interactive user home directories defined in the /etc/passwd file must exist.'
  desc 'If a user has a home directory defined that does not exist, the user may be given the / directory, by default, as the current working directory upon logon.  This could create a Denial of Service because the user would not be able to perform useful tasks in this location.'
  desc 'check', "Use pwck to verify assigned home directories exist.

# pwck

If any user's assigned home directory does not exist, this is a finding."
  desc 'fix', 'If a user has no home directory, determine why. If possible, delete accounts without a home directory. If the account is valid, then create the home directory using the appropriate system administration utility or manually.

For instance: mkdir directoryname; copy the skeleton files into the directory; chown accountname for the new directory and the skeleton files. Document all changes.'
  impact 0.3
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19780r568825_chk'
  tag severity: 'low'
  tag gid: 'V-218305'
  tag rid: 'SV-218305r603259_rule'
  tag stig_id: 'GEN001460'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19778r568826_fix'
  tag 'documentable'
  tag legacy: ['V-900', 'SV-64579']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
