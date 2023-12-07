control 'SV-38879' do
  title 'Run control scripts library search paths must contain only authorized paths.'
  desc 'The library search path environment variable(s) contains a list of directories for the dynamic linker to search to find libraries. If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, two consecutive colons, or a single period, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Verify run control scripts' library search paths. 

Procedure:
# grep -r LIBPATH /etc/rc*

This variable is formatted as a colon-separated list of paths.

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the run control script and remove the relative path entries from the library search path variables that have not been documented with the ISSO.  

Edit the run control script and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37236r4_chk'
  tag severity: 'medium'
  tag gid: 'V-22354'
  tag rid: 'SV-38879r3_rule'
  tag stig_id: 'GEN001605'
  tag gtitle: 'GEN001605'
  tag fix_id: 'F-26197r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
