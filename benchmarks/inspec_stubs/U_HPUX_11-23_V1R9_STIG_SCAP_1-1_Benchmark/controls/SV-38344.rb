control 'SV-38344' do
  title "Run control scripts' lists of preloaded libraries must contain only absolute paths."
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary.  If this list contains paths to libraries relative to the current working directory, unintended libraries may be preloaded.  This variable is formatted as a space-separated list of libraries.  Paths starting with a slash (/) are absolute paths.'
  desc 'fix', 'Edit the run control script and remove any relative or empty  path entry from the library preload variable.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22355'
  tag rid: 'SV-38344r1_rule'
  tag stig_id: 'GEN001610'
  tag gtitle: 'GEN001610'
  tag fix_id: 'F-31721r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
