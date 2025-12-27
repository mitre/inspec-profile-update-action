control 'SV-38343' do
  title "Run control scripts' library search paths must contain only absolute paths."
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries. If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'fix', 'Edit the run control script and remove any relative or empty path entry from the library search path variable.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22354'
  tag rid: 'SV-38343r1_rule'
  tag stig_id: 'GEN001605'
  tag gtitle: 'GEN001605'
  tag fix_id: 'F-31700r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
