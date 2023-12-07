control 'SV-26357' do
  title "The root account's list of preloaded libraries must be empty."
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary.  If this list contains paths to libraries relative to the current working directory, unintended libraries may be preloaded.  This variable is formatted as a space-separated list of libraries.  Paths starting with (/) are absolute paths.'
  desc 'fix', 'Edit the root user initialization files and remove any definition of LD_PRELOAD.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22311'
  tag rid: 'SV-26357r1_rule'
  tag stig_id: 'GEN000950'
  tag gtitle: 'GEN000950'
  tag fix_id: 'F-23540r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
