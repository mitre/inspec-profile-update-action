control 'SV-34928' do
  title 'Local initialization files lists of preloaded libraries must contain only authorized paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If this list contains paths to libraries to the current working directory that have not been authorized, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries. Paths starting with a slash (/) are absolute paths.'
  desc 'check', %q(Verify local initialization files have library preload list path containing only authorized paths.
# cat /etc/passwd | cut -f 1,1 -d ":" | xargs -n1 -IUSER sh -c 'grep "LD_PRELOAD" ~USER/.*'

The LD_PRELOAD variable is a colon-delimited directory list. 

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding.)
  desc 'fix', 'Edit the local initialization file and remove any relative/empty path entry from the library LD_PRELOAD variable that has not been documented with the ISSO. 

Edit the local initialization file and remove any empty entry that is defined for the “LD_PRELOAD” variable.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36394r3_chk'
  tag severity: 'medium'
  tag gid: 'V-22364'
  tag rid: 'SV-34928r3_rule'
  tag stig_id: 'GEN001902'
  tag gtitle: 'GEN001902'
  tag fix_id: 'F-31733r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
