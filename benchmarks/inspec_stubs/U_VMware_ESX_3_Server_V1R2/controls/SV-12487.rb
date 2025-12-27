control 'SV-12487' do
  title "All local initialization files' executable search paths must contain only absolute paths."
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables.  If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands.  This variable is formatted as a colon-separated list of directories.  If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory.  Paths starting with a slash (/) are absolute paths.'
  desc 'check', %q(NOTE: The following must be done in the BASH shell.

Examine the PATH variable contained in any user's local initialization files to ensure the use of only absolute paths, using a command shell that supports the use of ~USER as USER's home directory.

# cat /etc/passwd | cut -f 1,1 -d ":" | xargs -n1 -IUSER sh -c 'grep -i PATH ~USER/.*'

The PATH variable is a colon-delimited directory list. 

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/) or other than "$PATH", it is a relative path and this is a finding.)
  desc 'fix', 'Edit the local initialization file(s) and remove the relative path entry from the PATH variable.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7951r4_chk'
  tag severity: 'medium'
  tag gid: 'V-11986'
  tag rid: 'SV-12487r4_rule'
  tag stig_id: 'GEN001900'
  tag gtitle: 'GEN001900'
  tag fix_id: 'F-11247r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
