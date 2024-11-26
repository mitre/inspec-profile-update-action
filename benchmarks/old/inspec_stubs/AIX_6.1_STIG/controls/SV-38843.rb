control 'SV-38843' do
  title 'Global initialization files lists of preloaded libraries must contain only authorized paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If this list contains paths to libraries to the current working directory that have not been authorized, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Check the global initialization files' library preload list. 

# grep LDR_PRELOAD /etc/profile /etc/bashrc /etc/security/.login /etc/environment /etc/security/environ

This variable is formatted as a colon-separated list of paths.

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the global initialization files and remove any relative path entries from the library preload list variable "LDR_PRELOAD" that have not been documented with the ISSO.

Edit the run control script and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37835r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22360'
  tag rid: 'SV-38843r3_rule'
  tag stig_id: 'GEN001850'
  tag gtitle: 'GEN001850'
  tag fix_id: 'F-33098r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
