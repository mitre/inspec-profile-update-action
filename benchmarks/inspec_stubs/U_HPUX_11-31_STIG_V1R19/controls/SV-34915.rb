control 'SV-34915' do
  title 'All local initialization files executable search paths must contain only authorized paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', %q(Verify local initialization files have executable search path containing only authorized paths.
# cat /etc/passwd | cut -f 1,1 -d ":" | xargs -n1 -I USER sh -c 'grep PATH ~USER/.*'

This variable is formatted as a colon-separated list of directories. 

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding.)
  desc 'fix', 'Edit the local initialization file and remove the relative path entries from the PATH variable that have not been documented with the ISSO.
 
Edit the local initialization file and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-37677r3_chk'
  tag severity: 'medium'
  tag gid: 'V-11986'
  tag rid: 'SV-34915r3_rule'
  tag stig_id: 'GEN001900'
  tag gtitle: 'GEN001900'
  tag fix_id: 'F-32917r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
