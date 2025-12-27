control 'SV-38351' do
  title "Local initialization files' library search paths must contain only absolute paths."
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries.  If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries.  This variable is formatted as a colon-separated list of directories.  If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is interpreted as the current working directory.  Paths starting with a slash (/) are absolute paths.'
  desc 'fix', "Edit the user's local initialization file(s) and remove any  relative/empty path entry from the library search LIBRARY_PATH and/or SHLIB_PATH variable(s)."
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22363'
  tag rid: 'SV-38351r1_rule'
  tag stig_id: 'GEN001901'
  tag gtitle: 'GEN001901'
  tag fix_id: 'F-31732r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
