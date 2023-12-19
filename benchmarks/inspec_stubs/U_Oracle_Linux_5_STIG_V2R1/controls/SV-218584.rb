control 'SV-218584' do
  title 'Management Information Base (MIB) files must not have extended ACLs.'
  desc 'The ability to read the MIB file could impart special knowledge to an intruder or malicious user about the ability to extract compromising information about the system or network.'
  desc 'check', "Check the file permissions for the MIB files.
# find / -name *.mib 
# ls -lL <mib file>

If the permissions include a '+', the file has an extended ACL. 

If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.

# setfacl --remove-all <mib file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20059r555950_chk'
  tag severity: 'medium'
  tag gid: 'V-218584'
  tag rid: 'SV-218584r603259_rule'
  tag stig_id: 'GEN005350'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20057r555951_fix'
  tag 'documentable'
  tag legacy: ['V-22450', 'SV-63437']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
