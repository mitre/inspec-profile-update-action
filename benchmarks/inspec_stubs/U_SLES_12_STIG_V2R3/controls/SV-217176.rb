control 'SV-217176' do
  title 'All SUSE operating system local interactive user initialization files executable search paths must contain only paths that resolve to the users home directory.'
  desc "The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory (other than the user's home directory), executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory. If deviations from the default system search path for the local interactive user are required, they must be documented with the Information System Security Officer (ISSO)."
  desc 'check', %q(Verify that all SUSE operating system local interactive user initialization files executable search path statements do not contain statements that will reference a working directory other than the user's home directory.

Check the executable search path statement for all operating system local interactive user initialization files in the users' home directory with the following commands:

Note: The example will be for the user "smithj", who has a home directory of "/home/smithj".

# sudo grep -i path /home/smithj/.*
/home/smithj/.bash_profile:PATH=$PATH:$HOME/.local/bin:$HOME/bin
/home/smithj/.bash_profile:export PATH

If any local interactive user initialization files have executable search path statements that include directories outside of their home directory, and the additional path statements are not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.)
  desc 'fix', 'Edit the SUSE operating system local interactive user initialization files to change any PATH variable statements for executables that reference directories other than their home directory. If a local interactive user requires path variables to reference a directory owned by the application, it must be documented with the ISSO.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18404r369684_chk'
  tag severity: 'medium'
  tag gid: 'V-217176'
  tag rid: 'SV-217176r603262_rule'
  tag stig_id: 'SLES-12-010770'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18402r369685_fix'
  tag 'documentable'
  tag legacy: ['SV-91915', 'V-77219']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
