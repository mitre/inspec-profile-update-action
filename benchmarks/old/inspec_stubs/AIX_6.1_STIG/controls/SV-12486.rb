control 'SV-12486' do
  title 'All global initialization files executable search paths must contain only authorized paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Check the global initialization files' executable search paths.

Procedure:
# grep -i PATH /etc/profile /etc/bashrc /etc/csh.login /etc/csh.cshrc /etc/environment /etc/.login /etc/security/environ

This variable is formatted as a colon-separated list of directories. 

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the global initialization file(s) with PATH variables containing relative paths and remove any relative path form the PATH variables that have not been documented with the ISSO.  

Edit the global initialization file(s) and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-7950r4_chk'
  tag severity: 'medium'
  tag gid: 'V-11985'
  tag rid: 'SV-12486r4_rule'
  tag stig_id: 'GEN001840'
  tag gtitle: 'GEN001840'
  tag fix_id: 'F-11246r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
