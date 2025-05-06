control 'SV-226557' do
  title 'Local initialization files library search paths must contain only authorized paths.'
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries. If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "NOTE: This command should be used in the BASH shell.

Verify local initialization files have library search path containing only authorized paths.
# cut -d : -f 1 /etc/passwd | xargs -n1 -IUSER sh -c 'grep -l LD_LIBRARY_PATH ~USER/.*'

This variable is formatted as a colon-separated list of directories.

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the local initialization file and remove the relative path entries from the library search path variables that have not been documented with the ISSO.  

Edit the local initialization file and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28718r483080_chk'
  tag severity: 'medium'
  tag gid: 'V-226557'
  tag rid: 'SV-226557r603265_rule'
  tag stig_id: 'GEN001901'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28706r483081_fix'
  tag 'documentable'
  tag legacy: ['V-22363', 'SV-26486']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
