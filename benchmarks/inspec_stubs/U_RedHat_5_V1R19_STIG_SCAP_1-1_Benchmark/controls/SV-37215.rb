control 'SV-37215' do
  title 'Run control scripts lists of preloaded libraries must contain only authorized paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If this list contains paths to libraries to the current working directory that have not been authorized, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries. Paths starting with a slash (/) are absolute paths.'
  desc 'fix', 'Edit the run control script and remove the relative path entries from the library preload variables that are not documented with the ISSO.   

Edit the run control script and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22355'
  tag rid: 'SV-37215r3_rule'
  tag stig_id: 'GEN001610'
  tag gtitle: 'GEN001610'
  tag fix_id: 'F-32781r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
