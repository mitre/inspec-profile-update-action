control 'SV-218248' do
  title 'The root accounts executable search path must be the must contain only authorized paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Entries starting with a slash (/) are absolute paths.'
  desc 'check', "To view the root user's PATH, log in as the root user, and execute:

# env | grep PATH

This variable is formatted as a colon-separated list of directories.
Relative path entries must be document with the ISSO.

Such as a leading or trailing colon, two consecutive colons, or a single period this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', "Edit the root user's local initialization files ~/.profile,~/.bashrc (assuming root shell is bash). 

Remove any relative path entries that have not been documented with the ISSO.

Remove any empty path entries that are defined in these files."
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19723r561425_chk'
  tag severity: 'medium'
  tag gid: 'V-218248'
  tag rid: 'SV-218248r603259_rule'
  tag stig_id: 'GEN000940'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19721r561426_fix'
  tag 'documentable'
  tag legacy: ['V-776', 'SV-64373']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
