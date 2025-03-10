control 'SV-26010' do
  title "Local initialization files' library search paths must contain only absolute paths."
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries.  If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries.  This variable is formatted as a colon-separated list of directories.  If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is interpreted as the current working directory.  Paths starting with a slash (/) are absolute paths.'
  desc 'check', 'Verify local initialization files have library search paths containing only absolute paths. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. If an entry begins with a character other than a slash (/), this is a relative path, and this is a finding.'
  desc 'fix', 'Edit the local initialization file(s) and remove the relative path entry from the library search path.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29187r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22363'
  tag rid: 'SV-26010r1_rule'
  tag stig_id: 'GEN001901'
  tag gtitle: 'GEN001901'
  tag fix_id: 'F-26204r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
