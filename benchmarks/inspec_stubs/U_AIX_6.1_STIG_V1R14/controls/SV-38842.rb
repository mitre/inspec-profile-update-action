control 'SV-38842' do
  title 'Global initialization files library search paths must contain only authorized paths.'
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries. If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', 'Edit the global initialization files /etc/profile /etc/bashrc /etc/security/.login /etc/environment /etc/security/environ and remove relative entries from the library search path that have not been documented with the ISSO.

Edit the run control script and remove any empty entry that is defined.

#vi /etc/profile /etc/bashrc /etc/security/.login /etc/environment /etc/security/environ'
  desc 'fix', 'Edit the global initialization files /etc/profile /etc/bashrc /etc/security/.login /etc/environment /etc/security/environ and remove relative entries from the library search path variables.

#vi /etc/profile /etc/bashrc /etc/security/.login /etc/environment /etc/security/environ'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37171r4_chk'
  tag severity: 'medium'
  tag gid: 'V-22359'
  tag rid: 'SV-38842r3_rule'
  tag stig_id: 'GEN001845'
  tag gtitle: 'GEN001845'
  tag fix_id: 'F-33097r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
