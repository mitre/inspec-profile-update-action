control 'SV-45064' do
  title 'Run control scripts executable search paths must contain only absolute paths.'
  desc 'The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables.  If this path includes the current working directory or other relative paths, executables in these directories may be executed instead of system commands.  This variable is formatted as a colon-separated list of directories.  If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is interpreted as the current working directory.  Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Verify run control scripts' library search paths.
# grep -r PATH /etc/rc* /etc/init.d
This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. If an entry begins with a character other than a slash (/), this is a relative path, this is a finding."
  desc 'fix', 'Edit the run control script and remove the relative path entry from the executable search path variable.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42435r1_chk'
  tag severity: 'medium'
  tag gid: 'V-907'
  tag rid: 'SV-45064r1_rule'
  tag stig_id: 'GEN001600'
  tag gtitle: 'GEN001600'
  tag fix_id: 'F-38470r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
