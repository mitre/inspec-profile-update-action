control 'SV-38344' do
  title 'Run control scripts lists of preloaded libraries must contain only authorized paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If this list contains paths to libraries to the current working directory that have not been authorized, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries. Paths starting with a slash (/) are absolute paths.'
  desc 'check', 'Verify the run control scripts library preload paths do not contain references to the current working directory or other relative paths in any script where the following library PATH variable(s) occurs that have not been authorized by the ISSO.
# egrep "LD_PRELOAD" /sbin/init.d/[a-z,A-Z,0-9]*

This variable is formatted as a colon-separated list of paths.

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding.'
  desc 'fix', 'Edit the run control script and remove any relative entries from the library preload variables that have not been documented with the ISSO.  
 
Edit the run control script and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36383r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22355'
  tag rid: 'SV-38344r3_rule'
  tag stig_id: 'GEN001610'
  tag gtitle: 'GEN001610'
  tag fix_id: 'F-31721r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
