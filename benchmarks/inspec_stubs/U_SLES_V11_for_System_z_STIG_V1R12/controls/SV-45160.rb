control 'SV-45160' do
  title 'Local initialization files library search paths must contain only absolute paths.'
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries.  If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries.  This variable is formatted as a colon-separated list of directories.  If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is interpreted as the current working directory.  Paths starting with a slash (/) are absolute paths.'
  desc 'check', 'Verify local initialization files have library search path containing only absolute paths.
Procedure:
# cut -d: -f6 /etc/passwd |xargs -n1 -IDIR find DIR -name ".*" -type f -maxdepth 1 -exec grep -H LD_LIBRARY_PATH {} \\;
This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. If an entry begins with a character other than a slash (/) this is a relative path, this is a finding.'
  desc 'fix', 'Edit the local initialization file and remove the relative path entry from the library search path variable.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42504r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22363'
  tag rid: 'SV-45160r1_rule'
  tag stig_id: 'GEN001901'
  tag gtitle: 'GEN001901'
  tag fix_id: 'F-38557r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
