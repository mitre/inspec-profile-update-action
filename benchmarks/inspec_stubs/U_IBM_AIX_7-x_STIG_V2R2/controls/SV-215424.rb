control 'SV-215424' do
  title 'The local initialization file library search paths must contain only absolute paths on AIX.'
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries. If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is interpreted as the current working directory.'
  desc 'check', %q(Identify local initialization files that have library search paths:  

# cat /etc/passwd | cut -f 1,1 -d ":" | xargs -n1 -IUSER sh -c 'grep -l LIB ~USER/.*' 
/root/.sh_history
/home/doejohn/.profile
/home/doejane/.profile

For each file identified above, verify the search path contains only absolute paths:

Note: The "LIBPATH" and "LD_LIBRARY_PATH" variables are formatted as a colon-separated list of directories.

# cat <local_initilization_file> | grep -Ei 'lib|library'
LD_LIBRARY_PATH=/usr/lib
LIBPATH=/usr/lib

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/) or other than "$PATH", it is a relative path, and this is a finding.)
  desc 'fix', 'Edit the local initialization file(s) and remove the relative path entry from the library search path.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16622r294723_chk'
  tag severity: 'medium'
  tag gid: 'V-215424'
  tag rid: 'SV-215424r508663_rule'
  tag stig_id: 'AIX7-00-003129'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16620r294724_fix'
  tag 'documentable'
  tag legacy: ['V-91697', 'SV-101795']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
