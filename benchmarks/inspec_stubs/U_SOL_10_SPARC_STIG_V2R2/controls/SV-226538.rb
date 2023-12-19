control 'SV-226538' do
  title 'Run control scripts executable search paths must contain only authorized paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Verify run control scripts' executable search paths. 

Procedure: 

# find /etc/rc* /etc/init.d /lib/svc/method -type f -print | xargs grep -w PATH

This variable is formatted as a colon-separated list of directories. 

Relative path entries must be document with the ISSO.

If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the run control script and remove the relative path entries from the executable search path variable that are not documented with the ISSO.   

Edit the run control script and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28699r483008_chk'
  tag severity: 'medium'
  tag gid: 'V-226538'
  tag rid: 'SV-226538r603265_rule'
  tag stig_id: 'GEN001600'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28687r483009_fix'
  tag 'documentable'
  tag legacy: ['V-907', 'SV-39837']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
