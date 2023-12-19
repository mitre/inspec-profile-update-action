control 'SV-38349' do
  title "Global initialization files' lists of preloaded libraries must contain only absolute paths."
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary.  If this list contains paths to libraries relative to the current working directory, unintended libraries may be preloaded.  This variable is formatted as a space-separated list of libraries.  Paths starting with a slash (/) are absolute paths.'
  desc 'fix', 'Edit the global initialization file and remove the relative path entry from the library preload variable.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22360'
  tag rid: 'SV-38349r1_rule'
  tag stig_id: 'GEN001850'
  tag gtitle: 'GEN001850'
  tag fix_id: 'F-31728r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
