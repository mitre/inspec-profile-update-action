control 'SV-38881' do
  title 'Run control scripts lists of preloaded libraries must contain only authorized paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If this list contains paths to libraries to the current working directory that have not been authorized, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Verify run control scripts' library preload list. 

# grep -r LDR_PRELOAD /etc/rc*

This variable is formatted as a colon-separated list of paths.

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', "Edit the run control scripts' library preload list and remove relative paths that have not been documented with the ISSO.   

Edit the run control script and remove any empty entry that is defined."
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37237r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22355'
  tag rid: 'SV-38881r3_rule'
  tag stig_id: 'GEN001610'
  tag gtitle: 'GEN001610'
  tag fix_id: 'F-26198r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
