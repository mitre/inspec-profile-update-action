control 'SV-218319' do
  title 'Run control scripts library search paths must contain only authorized paths.'
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries. If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Verify run control scripts' library search paths.
# grep -r LD_LIBRARY_PATH /etc/rc* /etc/init.d

This variable is formatted as a colon-separated list of directories.

Such as a leading or trailing colon, two consecutive colons, or a single period, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the run control script and remove the relative path entries from the library search path variables that are not documented with the ISSO.
 
Remove any empty path entries that are defined in these files.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19794r568834_chk'
  tag severity: 'medium'
  tag gid: 'V-218319'
  tag rid: 'SV-218319r603259_rule'
  tag stig_id: 'GEN001605'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19792r568835_fix'
  tag 'documentable'
  tag legacy: ['V-22354', 'SV-63851']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
