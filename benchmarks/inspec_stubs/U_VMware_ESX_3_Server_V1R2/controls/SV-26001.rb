control 'SV-26001' do
  title "Run control scripts' library search paths must contain only absolute paths."
  desc 'The library search path environment variable(s) contain a list of directories for the dynamic linker to search to find libraries. If this path includes the current working directory or other relative paths, libraries in these directories may be loaded instead of system libraries. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is interpreted as the current working directory. Paths starting with a slash (/) are absolute paths.'
  desc 'check', "Verify run control scripts' library search paths. 
The variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon, or two consecutive colons, this is a finding. If an entry begins with a character other than a slash (/), this is a relative path, and this is a finding."
  desc 'fix', "Edit run control scripts' library search path variables. Remove empty entries or entries that are not absolute paths."
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29183r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22354'
  tag rid: 'SV-26001r1_rule'
  tag stig_id: 'GEN001605'
  tag gtitle: 'GEN001605'
  tag fix_id: 'F-26197r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
