control 'SV-45066' do
  title 'Run control scripts library search paths must contain only absolute paths.'
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries. If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Verify run control scripts' library search paths.
# grep -r LD_LIBRARY_PATH /etc/rc* /etc/init.d
This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. If an entry begins with a character other than a slash (/) this is a relative path, this is a finding."
  desc 'fix', 'Edit the run control script and remove the relative path entry from the library search path variable.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42437r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22354'
  tag rid: 'SV-45066r1_rule'
  tag stig_id: 'GEN001605'
  tag gtitle: 'GEN001605'
  tag fix_id: 'F-38472r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
