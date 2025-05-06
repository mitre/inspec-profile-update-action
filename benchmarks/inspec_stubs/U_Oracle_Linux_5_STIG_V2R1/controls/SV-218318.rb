control 'SV-218318' do
  title 'Run control scripts executable search paths must contain only authorized paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Verify run control scripts' library search paths.

# grep -r '\\bPATH\\b' /etc/rc* /etc/init.d

This variable is formatted as a colon-separated list of directories.

Such as a leading or trailing colon, two consecutive colons, or a single period.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the run control script and remove any relative path entries from the executable search path variable that are not documented with the ISSO. 

Remove any empty path entries that are defined in these files.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19793r568831_chk'
  tag severity: 'medium'
  tag gid: 'V-218318'
  tag rid: 'SV-218318r603259_rule'
  tag stig_id: 'GEN001600'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19791r568832_fix'
  tag 'documentable'
  tag legacy: ['V-907', 'SV-63849']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
