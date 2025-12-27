control 'SV-38451' do
  title 'The root accounts executable search path must contain only authorized paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Entries starting with a slash (/) are absolute paths.'
  desc 'check', "To view the root user's PATH, log in as the root user, and execute:
# env | grep PATH

This variable is formatted as a colon-separated list of directories.
 
If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', "Edit the root user's local initialization files and remove any relative path entries that have not been documented with the ISSO.

Edit the root user’s local initialization files and remove any empty entry that is defined."
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36274r3_chk'
  tag severity: 'medium'
  tag gid: 'V-776'
  tag rid: 'SV-38451r3_rule'
  tag stig_id: 'GEN000940'
  tag gtitle: 'GEN000940'
  tag fix_id: 'F-31531r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
