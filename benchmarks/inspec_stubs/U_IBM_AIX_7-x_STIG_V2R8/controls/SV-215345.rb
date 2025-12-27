control 'SV-215345' do
  title 'AIX run control scripts executable search paths must contain only absolute paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands.'
  desc 'check', %q(Verify run control scripts' library search paths by running: 

# grep -r PATH /etc/rc* 
/etc/rc:PATH=/usr/sbin:/usr/bin:/usr/ucb:/etc
/etc/rc:export PATH ODMDIR
/etc/rc.C2:export PATH=/usr/bin:/etc:/usr/sbin:/sbin:/usr/ucb
/etc/rc.CC:export PATH=/usr/bin:/etc:/usr/sbin:/sbin:/usr/ucb
/etc/rc.bsdnet:export PATH=/usr/bin:/usr/sbin:$PATH

This variable is formatted as a colon-separated list of directories. 

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/) or other than "$PATH", it is a relative path, this is a finding.)
  desc 'fix', 'Edit the run control script and remove the relative path entry from the executable search path variable.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16543r294486_chk'
  tag severity: 'medium'
  tag gid: 'V-215345'
  tag rid: 'SV-215345r508663_rule'
  tag stig_id: 'AIX7-00-003039'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16541r294487_fix'
  tag 'documentable'
  tag legacy: ['V-91637', 'SV-101735']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
