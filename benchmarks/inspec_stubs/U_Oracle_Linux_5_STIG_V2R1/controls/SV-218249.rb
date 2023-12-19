control 'SV-218249' do
  title 'The root accounts library search path must be the system default and must contain only absolute paths.'
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries.  If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries.  This variable is formatted as a colon-separated list of directories.  If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory.  Entries starting with a slash (/) are absolute paths.'
  desc 'check', 'Check the LD_LIBRARY_PATH environment variable is empty or not defined for the root user.
# echo $LD_LIBRARY_PATH
If a path list is returned, this is a finding.'
  desc 'fix', 'Edit the root user initialization files and remove any definition of LD_LIBRARY_PATH.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19724r568687_chk'
  tag severity: 'medium'
  tag gid: 'V-218249'
  tag rid: 'SV-218249r603259_rule'
  tag stig_id: 'GEN000945'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19722r568688_fix'
  tag 'documentable'
  tag legacy: ['V-22310', 'SV-64377']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
