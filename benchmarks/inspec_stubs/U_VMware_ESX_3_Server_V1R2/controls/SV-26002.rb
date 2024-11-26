control 'SV-26002' do
  title "Run control scripts' lists of preloaded libraries must contain only absolute paths."
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary.  If this list contains paths to libraries relative to the current working directory, unintended libraries may be preloaded.  This variable is formatted as a space-separated list of libraries.  Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Check that run control scripts' library preload list. This variable is formatted as a colon-separated list of paths. If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. If an entry begins with a character other than a slash (/), this is a relative path, and this is a finding."
  desc 'fix', "Edit the run control scripts' library preload list and remove relative paths."
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29184r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22355'
  tag rid: 'SV-26002r1_rule'
  tag stig_id: 'GEN001610'
  tag gtitle: 'GEN001610'
  tag fix_id: 'F-26198r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
