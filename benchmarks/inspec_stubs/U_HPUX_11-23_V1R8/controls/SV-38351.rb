control 'SV-38351' do
  title "Local initialization files' library search paths must contain only absolute paths."
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries.  If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries.  This variable is formatted as a colon-separated list of directories.  If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is interpreted as the current working directory.  Paths starting with a slash (/) are absolute paths.'
  desc 'check', %q(Verify that any PATH variable contained in a user's local initialization files uses only absolute paths.
# cat /etc/passwd | cut -f 1,1 -d ":" | xargs -n1 -IUSER sh -c 'egrep -i "LD_LIBRARY_PATH|SHLIB_PATH" ~USER/.*'

The PATH variable is a colon-delimited directory list. 

An empty entry is defined by a leading/trailing colon or two consecutive colons. 

A relative path is defined as an entry beginning with a character other than a slash (/).

If an empty or relative path is defined in the PATH variable, this is a finding.)
  desc 'fix', "Edit the user's local initialization file(s) and remove any  relative/empty path entry from the library search LIBRARY_PATH and/or SHLIB_PATH variable(s)."
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36391r1_chk'
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
