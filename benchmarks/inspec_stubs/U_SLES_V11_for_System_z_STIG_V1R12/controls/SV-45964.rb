control 'SV-45964' do
  title 'Management Information Base (MIB) files must not have extended ACLs.'
  desc 'The ability to read the MIB file could impart special knowledge to an intruder or malicious user about the ability to extract compromising information about the system or network.'
  desc 'check', "Check the file permissions for the MIB files.
# find / -name *mib* -o -name *MIB* | xargs ls -lL

If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all <mib file>'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43246r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22450'
  tag rid: 'SV-45964r1_rule'
  tag stig_id: 'GEN005350'
  tag gtitle: 'GEN005350'
  tag fix_id: 'F-39329r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
