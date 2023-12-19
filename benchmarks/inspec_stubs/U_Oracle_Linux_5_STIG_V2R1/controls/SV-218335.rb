control 'SV-218335' do
  title 'Global initialization files library search paths must contain only authorized paths.'
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries. If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries. This variable is formatted as a colon-separated list of directories, such as a leading or trailing colon, two consecutive colons, or a single period; this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Check the global initialization files' library search paths.

Procedure:
# grep LD_LIBRARY_PATH /etc/bashrc /etc/csh.cshrc /etc/csh.login /etc/csh.logout /etc/environment /etc/ksh.kshrc /etc/profile /etc/suid_profile /etc/profile.d/*

This variable is formatted as a colon-separated list of directories.

Such as a leading or trailing colon, two consecutive colons, or a single period, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the global initialization file and remove the relative path entries from the library search path variables that have not been documented with the ISSO.   

Remove any empty path entries that are defined in these files.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19810r568870_chk'
  tag severity: 'medium'
  tag gid: 'V-218335'
  tag rid: 'SV-218335r603259_rule'
  tag stig_id: 'GEN001845'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19808r568871_fix'
  tag 'documentable'
  tag legacy: ['V-22359', 'SV-63331']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
