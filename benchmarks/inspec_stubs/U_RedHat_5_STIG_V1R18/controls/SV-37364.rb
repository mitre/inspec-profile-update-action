control 'SV-37364' do
  title "The root account's list of preloaded libraries must be empty."
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary.  If this list contains paths to libraries relative to the current working directory, unintended libraries may be preloaded.  This variable is formatted as a space-separated list of libraries.  Paths starting with (/) are absolute paths.'
  desc 'check', 'Check the LD_PRELOAD environment variable is empty or not defined for the root user.
# echo $LD_PRELOAD
If a path list is returned, this is a finding.'
  desc 'fix', 'Edit the root user initialization files and remove any definition of LD_PRELOAD.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36054r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22311'
  tag rid: 'SV-37364r1_rule'
  tag stig_id: 'GEN000950'
  tag gtitle: 'GEN000950'
  tag fix_id: 'F-31298r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
