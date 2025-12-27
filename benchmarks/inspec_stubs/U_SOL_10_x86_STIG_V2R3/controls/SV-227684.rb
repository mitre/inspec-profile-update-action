control 'SV-227684' do
  title 'Local initialization files lists of preloaded libraries must contain only authorized paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary If this list contains paths to libraries to the current working directory that have not been authorized, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "NOTE: The following must be done in the BASH shell

Verify local initialization files have library preload list containing only authorized paths.
# cut -d : -f 1 /etc/passwd | xargs -n1 -IUSER sh -c 'grep -l LD_PRELOAD ~USER/.*'

This variable is formatted as a colon-separated list of paths.

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the local initialization file and remove the relative path entries from the library preload variables that have not been documented with the ISSO. 
  
Edit the local initialization file(s) and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29846r488633_chk'
  tag severity: 'medium'
  tag gid: 'V-227684'
  tag rid: 'SV-227684r603266_rule'
  tag stig_id: 'GEN001902'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29834r488634_fix'
  tag 'documentable'
  tag legacy: ['V-22364', 'SV-26488']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
