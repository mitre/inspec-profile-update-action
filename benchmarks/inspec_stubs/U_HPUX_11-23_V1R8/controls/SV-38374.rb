control 'SV-38374' do
  title 'Management Information Base (MIB) files must not have extended ACLs.'
  desc 'The ability to read the MIB file could impart special knowledge to an intruder or malicious user about the ability to extract compromising information about the system or network.'
  desc 'check', 'Check the file permissions for the MIB files. 
# find / -type f -name *.mib -exec ls -lL {} \\;

If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z <mib file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36614r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22450'
  tag rid: 'SV-38374r1_rule'
  tag stig_id: 'GEN005350'
  tag gtitle: 'GEN005350'
  tag fix_id: 'F-31980r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
