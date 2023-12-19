control 'SV-227682' do
  title 'All local initialization files executable search paths must contain only authorized paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', %q(NOTE: The following must be done in the BASH shell.

Examine the PATH variable contained in any user's local initialization files using a command shell that supports the use of ~USER as USER's home directory.

# cat /etc/passwd | cut -f 1,1 -d ":" | xargs -n1 -IUSER sh -c 'grep -i PATH ~USER/.*'

The PATH variable is a colon-delimited directory list. 

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding.)
  desc 'fix', 'Edit the local initialization file(s) and remove the relative path entries from the PATH variable that have not been documented with the ISSO.   

Edit the local initialization file(s) and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29844r488627_chk'
  tag severity: 'medium'
  tag gid: 'V-227682'
  tag rid: 'SV-227682r603266_rule'
  tag stig_id: 'GEN001900'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29832r488628_fix'
  tag 'documentable'
  tag legacy: ['V-11986', 'SV-12487']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
