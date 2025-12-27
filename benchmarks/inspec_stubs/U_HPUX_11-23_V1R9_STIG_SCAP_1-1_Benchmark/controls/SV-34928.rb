control 'SV-34928' do
  title "Local initialization files' lists of preloaded libraries must contain only absolute paths."
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary.  If this list contains paths to libraries relative to the current working directory, unintended libraries may be preloaded.  This variable is formatted as a space-separated list of libraries.  Paths starting with a slash (/) are absolute paths.'
  desc 'fix', 'Edit the local initialization file and remove any relative/empty path entry from the library LD_PRELOAD variable.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22364'
  tag rid: 'SV-34928r1_rule'
  tag stig_id: 'GEN001902'
  tag gtitle: 'GEN001902'
  tag fix_id: 'F-31733r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
