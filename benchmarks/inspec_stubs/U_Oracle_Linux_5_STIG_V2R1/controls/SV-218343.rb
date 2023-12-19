control 'SV-218343' do
  title 'Local initialization files lists of preloaded libraries must contain only authorized paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary. If an entry begins with a character other than a slash (/), or has If this list contains paths to libraries to the current working directory that have not been authorized, unintended libraries may be preloaded. This variable is formatted as a space-separated list of libraries. Paths starting with a slash (/) are absolute paths.'
  desc 'check', 'Verify local initialization files have library preload list containing only absolute paths.

NOTE: The following must be done in the BASH shell.

Procedure:
# cut -d: -f6 /etc/passwd |xargs -n1 -IDIR find DIR -name ".*" -type f -maxdepth 1 -exec grep -H LD_PRELOAD {} \\;

This variable is formatted as a colon-separated list of paths.

Such as a leading or trailing colon, two consecutive colons, or a single period, this is a finding.

If an entry begins with a character other than a slash (/), or has not been documented with the ISSO, this is a finding.'
  desc 'fix', 'Edit the local initialization file and remove any relative path entry from the library preload variable that has not been authorized by the ISSO.   

Remove any empty path entries that are defined in these files.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19818r569020_chk'
  tag severity: 'medium'
  tag gid: 'V-218343'
  tag rid: 'SV-218343r603259_rule'
  tag stig_id: 'GEN001902'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19816r569021_fix'
  tag 'documentable'
  tag legacy: ['V-22364', 'SV-63569']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
