control 'SV-215425' do
  title 'The local initialization file lists of preloaded libraries must contain only absolute paths on AIX.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If this list contains paths to libraries relative to the current working directory, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries.'
  desc 'check', %q(Identify local initialization files that have library search paths:  

# cat /etc/passwd | cut -f 1,1 -d ":" | xargs -n1 -IUSER sh -c 'grep -l LDR_PRELOAD ~USER/.*' 
/root/.sh_history
/home/doejohn/.profile
/home/doejane/.profile

For each file identified above, verify the search path contains only absolute paths:
Note: This variable is formatted as a colon-separated list of paths.

# cat <local_initilization_file> | grep -Ei 'ldr|preload'
LDR_PRELOAD=/usr/lib

If the paths listed have not been documented and authorized by the ISSO/ISSM, this is a finding.
If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. 
If an entry begins with a character other than a slash (/) or other than "$PATH", it is a relative path, and this is a finding.)
  desc 'fix', 'Edit the local initialization file and remove the relative path entry from the library preload variable "LDR_PRELOAD".'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16623r294726_chk'
  tag severity: 'medium'
  tag gid: 'V-215425'
  tag rid: 'SV-215425r508663_rule'
  tag stig_id: 'AIX7-00-003130'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16621r294727_fix'
  tag 'documentable'
  tag legacy: ['SV-101797', 'V-91699']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
