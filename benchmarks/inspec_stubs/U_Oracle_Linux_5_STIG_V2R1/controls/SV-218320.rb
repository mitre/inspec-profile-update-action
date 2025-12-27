control 'SV-218320' do
  title 'Run control scripts lists of preloaded libraries must contain only authorized paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If an entry begins with a character other than a slash (/), or has If this list contains paths to libraries to the current working directory that have not been authorized, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Verify run control scripts' library preload list.
# grep -r LD_PRELOAD /etc/rc* /etc/init.d

This variable is formatted as a colon-separated list of directories.

Such as a leading or trailing colon, two consecutive colons, or a single period, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the run control script and remove the relative path entries from the library preload variables that are not documented with the ISSO.   

Remove any empty path entries that are defined in these files.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19795r568837_chk'
  tag severity: 'medium'
  tag gid: 'V-218320'
  tag rid: 'SV-218320r603259_rule'
  tag stig_id: 'GEN001610'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19793r568838_fix'
  tag 'documentable'
  tag legacy: ['V-22355', 'SV-63853']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
