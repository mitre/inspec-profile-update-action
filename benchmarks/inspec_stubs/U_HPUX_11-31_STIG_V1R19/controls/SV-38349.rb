control 'SV-38349' do
  title 'Global initialization files lists of preloaded libraries must contain only authorized paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If this list contains paths to libraries to the current working directory that have not been authorized, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Check the global initialization files' library preload list.
# grep LD_PRELOAD /etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/environment /etc/.login

This variable is formatted as a colon-separated list of paths.

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the global initialization file and remove the relative path entry from the library preload list variables that have not been documented with the ISSO. 
  
Edit the global initialization file(s) and remove any empty entry that is defined for the library preload list.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36388r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22360'
  tag rid: 'SV-38349r3_rule'
  tag stig_id: 'GEN001850'
  tag gtitle: 'GEN001850'
  tag fix_id: 'F-31728r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
