control 'SV-227666' do
  title 'Run control scripts lists of preloaded libraries must contain only authorized paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If this list contains paths to libraries to the current working directory that have not been authorized, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Verify run control scripts' library preload list. 

Procedure:
# find /etc/rc* /etc/init.d -type f -print | xargs grep LD_PRELOAD


This variable is formatted as a colon-separated list of paths.

If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding."
  desc 'fix', 'Edit the run control script and remove the relative path entry from the library preload variables that are not documented with the ISSO. 

Edit the run control script and remove any empty entry that is defined.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29828r488564_chk'
  tag severity: 'medium'
  tag gid: 'V-227666'
  tag rid: 'SV-227666r603266_rule'
  tag stig_id: 'GEN001610'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29816r488565_fix'
  tag 'documentable'
  tag legacy: ['V-22355', 'SV-26464']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
