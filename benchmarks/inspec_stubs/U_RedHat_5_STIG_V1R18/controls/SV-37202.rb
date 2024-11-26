control 'SV-37202' do
  title 'Run control scripts executable search paths must contain only authorized paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Verify run control scripts' library search paths.

# grep -r '\\bPATH\\b' /etc/rc* /etc/init.d

This variable is formatted as a colon-separated list of directories.

Relative path entries must be documented with the ISSO.

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the run control script and remove any relative path entries from the executable search path variable that are not documented with the ISSO.   

Edit the run control script and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37533r6_chk'
  tag severity: 'medium'
  tag gid: 'V-907'
  tag rid: 'SV-37202r4_rule'
  tag stig_id: 'GEN001600'
  tag gtitle: 'GEN001600'
  tag fix_id: 'F-32779r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
