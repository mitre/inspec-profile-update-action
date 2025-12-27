control 'SV-25957' do
  title "The root account's library search path must be the system default and must contain only absolute paths."
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries. If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory. Entries starting with a slash (/) are absolute paths.'
  desc 'check', "Consult vendor documentation for the system's dynamic linker to determine which environment variables specify the library search path.  

List the root user's environment variables.
Procedure:
# env

Determine if the root user's library search path is different from the system default.  If so, this is a finding."
  desc 'fix', "Configure the root user's library search path to the system default."
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29099r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22310'
  tag rid: 'SV-25957r1_rule'
  tag stig_id: 'GEN000945'
  tag gtitle: 'GEN000945'
  tag fix_id: 'F-26100r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
