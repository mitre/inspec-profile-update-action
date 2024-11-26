control 'SV-25958' do
  title "The root account's list of preloaded libraries must be empty."
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary.  If this list contains paths to libraries relative to the current working directory, unintended libraries may be preloaded.  This variable is formatted as a space-separated list of libraries.  Paths starting with (/) are absolute paths.'
  desc 'check', "Consult vendor documentation for the system's dynamic linker to determine what environment variables are used to configure the list of preloaded libraries.  

List the root user's environment variables.
Procedure:
# env

Determine if the root account's list of preloaded libraries is empty.  If it is not, this is a finding."
  desc 'fix', "Empty the root account's list of preloaded libraries."
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29100r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22311'
  tag rid: 'SV-25958r1_rule'
  tag stig_id: 'GEN000950'
  tag gtitle: 'GEN000950'
  tag fix_id: 'F-26101r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
