control 'SV-44906' do
  title 'The root accounts library search path must be the system default and must contain only absolute paths.'
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries.  If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries.  This variable is formatted as a colon-separated list of directories.  If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory.  Entries starting with a slash (/) are absolute paths.'
  desc 'check', 'Check the LD_LIBRARY_PATH environment variable is empty or not defined for the root user.
# echo $LD_LIBRARY_PATH
If a path list is returned, this is a finding.'
  desc 'fix', 'Edit the root user initialization files and remove any definition of LD_LIBRARY_PATH.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42347r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22310'
  tag rid: 'SV-44906r1_rule'
  tag stig_id: 'GEN000945'
  tag gtitle: 'GEN000945'
  tag fix_id: 'F-38338r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
