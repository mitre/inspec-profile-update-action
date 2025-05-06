control 'SV-218341' do
  title 'All local initialization files executable search paths must contain only authorized paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories, such as a leading or trailing colon, two consecutive colons, or a single period; this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', 'Verify local initialization files have executable search path containing only absolute paths or relative paths are necessary and documented with the ISSO.

Procedure:

NOTE: This must be done in the BASH shell.

# cut -d: -f6 /etc/passwd |xargs -n1 -IDIR find DIR -name ".*" -type f -maxdepth 1 -exec grep -l PATH {} \\;

This variable is formatted as a colon-separated list of directories. 

Such as a leading or trailing colon, two consecutive colons, or a single period this is a finding.
 
If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding.'
  desc 'fix', 'Edit the local initialization file and remove the relative path entry from the executable search path variable. If this is not feasible, justify and document the necessity of having the relative path for a specific application with the ISSO.
   
Remove any empty path entries that are defined in these files.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19816r569014_chk'
  tag severity: 'medium'
  tag gid: 'V-218341'
  tag rid: 'SV-218341r603259_rule'
  tag stig_id: 'GEN001900'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19814r569015_fix'
  tag 'documentable'
  tag legacy: ['V-11986', 'SV-63541']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
