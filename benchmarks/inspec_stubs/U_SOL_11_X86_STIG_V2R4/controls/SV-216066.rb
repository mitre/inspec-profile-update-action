control 'SV-216066' do
  title 'Run control scripts executable search paths must contain only authorized paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Verify run control scripts' executable search paths. 

Procedure: 

# find /etc/rc* /etc/init.d /lib/svc/method -type f -print | xargs grep -i PATH

This variable is formatted as a colon-separated list of directories.

If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the run control script and remove the relative path entries from the executable search path variable that have not been documented with the ISSO.
  
Edit the run control script and remove any empty path entries from the file.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17304r372580_chk'
  tag severity: 'medium'
  tag gid: 'V-216066'
  tag rid: 'SV-216066r603268_rule'
  tag stig_id: 'SOL-11.1-020320'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17302r372581_fix'
  tag 'documentable'
  tag legacy: ['V-59831', 'SV-74261']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
