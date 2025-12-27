control 'SV-218336' do
  title 'Global initialization files lists of preloaded libraries must contain only authorized paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If an entry begins with a character other than a slash (/), or has If this list contains paths to libraries to the current working directory that have not been authorized, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Check the global initialization files' library preload list.
# grep -r LD_PRELOAD /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/csh.logout /etc/environment /etc/ksh.kshrc /etc/profile /etc/suid_profile /etc/profile.d/*

This variable is formatted as a colon-separated list of paths.

Such as a leading or trailing colon, two consecutive colons, or a single period, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the global initialization file and remove the relative path entry from the library preload variable that has not been authorized by the ISSO.   

Remove any empty path entries that are defined in these files.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19811r568873_chk'
  tag severity: 'medium'
  tag gid: 'V-218336'
  tag rid: 'SV-218336r603259_rule'
  tag stig_id: 'GEN001850'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19809r568874_fix'
  tag 'documentable'
  tag legacy: ['V-22360', 'SV-63335']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
