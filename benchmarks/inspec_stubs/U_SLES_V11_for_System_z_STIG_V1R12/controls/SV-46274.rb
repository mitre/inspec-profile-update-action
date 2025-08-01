control 'SV-46274' do
  title 'All local initialization files executable search paths must contain only absolute paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables.  If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands.  This variable is formatted as a colon-separated list of directories.  If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is interpreted as the current working directory.  Paths starting with a slash (/) are absolute paths.'
  desc 'check', 'Verify local initialization files have executable search paths containing only absolute paths or relative paths that have been documented by the ISSO.

Procedure:

NOTE: This must be done in the BASH shell.

# cut -d: -f6 /etc/passwd |xargs -n1 -IDIR find DIR -name ".*" -type f -maxdepth 1 -exec grep -l PATH {} \\;
This variable is formatted as a colon-separated list of directories. 

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding.'
  desc 'fix', 'Edit the local initialization file and remove the relative path entry from the executable search path variable. If this is not feasible, justify and document the necessity of having the relative path for a specific application with the ISSO.   

Edit the local initialization file and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-35985r5_chk'
  tag severity: 'medium'
  tag gid: 'V-11986'
  tag rid: 'SV-46274r1_rule'
  tag stig_id: 'GEN001900'
  tag gtitle: 'GEN001900'
  tag fix_id: 'F-31242r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
