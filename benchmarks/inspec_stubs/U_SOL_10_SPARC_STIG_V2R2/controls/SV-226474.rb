control 'SV-226474' do
  title 'The root accounts executable search path must contain only authorized paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Entries starting with a slash (/) are absolute paths.'
  desc 'check', "To view the root user's PATH, log in as the root user, and execute the following.
# env | grep PATH

This variable is formatted as a colon-separated list of directories. 

If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', "Edit the root user's local initialization files. Remove any empty path entries. Remove any relative path entries that have not been documented with the ISSO.

Edit the root user's local initialization files and remove any empty entry that is defined."
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36383r602752_chk'
  tag severity: 'medium'
  tag gid: 'V-226474'
  tag rid: 'SV-226474r603265_rule'
  tag stig_id: 'GEN000940'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36347r602753_fix'
  tag 'documentable'
  tag legacy: ['V-776', 'SV-776']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
