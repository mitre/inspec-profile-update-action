control 'SV-227678' do
  title 'Global initialization files lists of preloaded libraries must contain only authorized paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If this list contains paths to libraries to the current working directory that have not been authorized, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Check the global initialization files' library preload list. 

Procedure:
# grep LD_PRELOAD /etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/environment /etc/.login /etc/security/environ 

This variable is formatted as a colon-separated list of paths.

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the global initialization file(s) and remove the relative path entry from the library preload list variables that have not been documented with the ISSO.
  
Edit the global initialization file(s) and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29840r488612_chk'
  tag severity: 'medium'
  tag gid: 'V-227678'
  tag rid: 'SV-227678r603266_rule'
  tag stig_id: 'GEN001850'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29828r488613_fix'
  tag 'documentable'
  tag legacy: ['V-22360', 'SV-39839']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
