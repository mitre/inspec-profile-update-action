control 'SV-39102' do
  title 'Local initialization files lists of preloaded libraries must contain only authorized paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If this list contains paths to libraries to the current working directory that have not been authorized, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries. Paths starting with a slash (/) are absolute paths.'
  desc 'check', 'Verify local initialization files have library preload list containing only authorized paths.

Procedure:
# cat /etc/passwd | cut -f 1,1 -d ":" | xargs -n1 -IUSER sh -c "grep -l LDR_PRELOAD ~USER/.*"

This variable is formatted as a colon-separated list of paths.

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding.'
  desc 'fix', 'Edit the local initialization file and remove any relative path entries from the library preload variable "LDR_PRELOAD" that have not been documented with the ISSO.

Edit the local initialization file and remove any empty entry that is defined for the “LDR_PRELOAD” variable.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38085r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22364'
  tag rid: 'SV-39102r3_rule'
  tag stig_id: 'GEN001902'
  tag gtitle: 'GEN001902'
  tag fix_id: 'F-33354r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
