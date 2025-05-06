control 'SV-37305' do
  title 'Local initialization files library search paths must contain only authorized paths.'
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries. If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', 'Verify local initialization files have library search paths containing only authorized paths.

Procedure:

NOTE: This must be done in the BASH shell.

# cut -d: -f6 /etc/passwd |xargs -n1 -IDIR find DIR -name ".*" -type f -maxdepth 1 -exec grep -H LD_LIBRARY_PATH {} \\;

This variable is formatted as a colon-separated list of directories.

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding.'
  desc 'fix', 'Edit the local initialization file and remove any relative path entries that have not been documented with the ISSO.

Edit the local initialization file and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36000r4_chk'
  tag severity: 'medium'
  tag gid: 'V-22363'
  tag rid: 'SV-37305r4_rule'
  tag stig_id: 'GEN001901'
  tag gtitle: 'GEN001901'
  tag fix_id: 'F-31253r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
