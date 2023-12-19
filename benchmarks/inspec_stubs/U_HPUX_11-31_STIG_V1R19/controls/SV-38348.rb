control 'SV-38348' do
  title 'Global initialization files library search paths must contain only authorized paths.'
  desc 'The library search path environment variable(s) contains a list of directories for the dynamic linker to search to find libraries. If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', %q(Check the global initialization files' library search path.
# egrep "LD_LIBRARY_PATH|SHLIB_PATH" /etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/environment /etc/.login

This variable is formatted as a colon-separated list of paths.

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding.)
  desc 'fix', 'Edit the global initialization file and remove the relative path entries from the library search path variables that have not been documented with the ISSO.
 
Edit the global initialization file and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36387r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22359'
  tag rid: 'SV-38348r3_rule'
  tag stig_id: 'GEN001845'
  tag gtitle: 'GEN001845'
  tag fix_id: 'F-31727r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
