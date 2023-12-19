control 'SV-38818' do
  title 'Management Information Base (MIB) files must not have extended ACLs.'
  desc 'The ability to read the MIB file could impart special knowledge to an intruder or malicious user about the ability to extract compromising information about the system or network.'
  desc 'check', 'Check the file permissions for the MIB files.
# find / -name *.mib -print
# aclget [mib file]
If the extended attributes are not disabled, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the MIB file(s) and change extended attributes to disabled.
  
#acledit [mib file]'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37059r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22450'
  tag rid: 'SV-38818r1_rule'
  tag stig_id: 'GEN005350'
  tag gtitle: 'GEN005350'
  tag fix_id: 'F-32327r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
