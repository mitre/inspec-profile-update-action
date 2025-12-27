control 'SV-45161' do
  title 'Local initialization files lists of preloaded libraries must contain only absolute paths.'
  desc 'The library preload list environment variable contains a list of libraries for the dynamic linker to load before loading the libraries required by the binary.  If this list contains paths to libraries relative to the current working directory, unintended libraries may be preloaded.  This variable is formatted as a space-separated list of libraries.  Paths starting with a slash (/) are absolute paths.'
  desc 'check', 'Verify local initialization files have library preload list containing only absolute paths.

Procedure:
# cut -d: -f6 /etc/passwd |xargs -n1 -IDIR find DIR -name ".*" -type f -maxdepth 1 -exec grep -H LD_PRELOAD {} \\;
This variable is formatted as a colon-separated list of paths. If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. If an entry begins with a character other than a slash (/) this is a relative path, this is a finding.'
  desc 'fix', 'Edit the local initialization file and remove the relative path entry from the library preload variable.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42505r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22364'
  tag rid: 'SV-45161r1_rule'
  tag stig_id: 'GEN001902'
  tag gtitle: 'GEN001902'
  tag fix_id: 'F-38558r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
