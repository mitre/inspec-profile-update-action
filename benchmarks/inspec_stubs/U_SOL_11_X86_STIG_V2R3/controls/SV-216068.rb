control 'SV-216068' do
  title 'Run control scripts lists of preloaded libraries must contain only authorized paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If this list contains paths to libraries to the current working directory that have not been authorized, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Verify run control scripts' library preload list. 

Procedure:

# find /etc/rc* /etc/init.d -type f -print | xargs grep LD_PRELOAD

This variable is formatted as a colon-separated list of paths.

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the run control script and remove the relative path entries from the library preload variables that have not been documented with the ISSO.   

Edit the run control script and remove any empty path entries from the file.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17306r372586_chk'
  tag severity: 'medium'
  tag gid: 'V-216068'
  tag rid: 'SV-216068r603268_rule'
  tag stig_id: 'SOL-11.1-020340'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17304r372587_fix'
  tag 'documentable'
  tag legacy: ['SV-74265', 'V-59835']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
