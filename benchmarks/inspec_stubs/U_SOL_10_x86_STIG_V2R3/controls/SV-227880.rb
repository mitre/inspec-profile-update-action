control 'SV-227880' do
  title 'Management Information Base (MIB) files must not have extended ACLs.'
  desc 'The ability to read the MIB file could impart special knowledge to an intruder or malicious user about the ability to extract compromising information about the system or network.'
  desc 'check', %q(Check the modes for all Management Information Base (MIB) files on the system.

# find /etc/sma/snmp/ /etc/snmp/conf/ /var/sma_snmp/ /usr/sfw/lib/sma_snmp/ -type f | grep -i mib | egrep -v '\.conf$' | xargs ls -lL

If the permissions include a "+", the file has an extended ACL, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- [mib file]'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30042r490036_chk'
  tag severity: 'medium'
  tag gid: 'V-227880'
  tag rid: 'SV-227880r603266_rule'
  tag stig_id: 'GEN005350'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30030r490037_fix'
  tag 'documentable'
  tag legacy: ['V-22450', 'SV-26727']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
