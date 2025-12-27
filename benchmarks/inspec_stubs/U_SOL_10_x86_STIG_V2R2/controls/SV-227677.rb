control 'SV-227677' do
  title 'Global initialization files library search paths must contain only authorized paths.'
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries. If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Check the global initialization files' library search paths.
# grep LD_LIBRARY_PATH /etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/environment /etc/.login /etc/security/environ

This variable is formatted as a colon-separated list of directories.

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the global initialization file and remove the relative path entries from the library search path variables that have not been documented with the ISSO.   

Edit the global initialization file(s) and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29839r488609_chk'
  tag severity: 'medium'
  tag gid: 'V-227677'
  tag rid: 'SV-227677r603266_rule'
  tag stig_id: 'GEN001845'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29827r488610_fix'
  tag 'documentable'
  tag legacy: ['V-22359', 'SV-26478']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
