control 'SV-38349' do
  title "Global initialization files' lists of preloaded libraries must contain only absolute paths."
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary.  If this list contains paths to libraries relative to the current working directory, unintended libraries may be preloaded.  This variable is formatted as a space-separated list of libraries.  Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Check the global initialization files' library preload list.
# grep  LD_PRELOAD /etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/environment /etc/.login

This variable is formatted as a colon-separated list of paths. If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. If an entry begins with a character other than a slash (/) this is a relative path, and this is a finding."
  desc 'fix', 'Edit the global initialization file and remove the relative path entry from the library preload variable.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36388r1_chk'
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
