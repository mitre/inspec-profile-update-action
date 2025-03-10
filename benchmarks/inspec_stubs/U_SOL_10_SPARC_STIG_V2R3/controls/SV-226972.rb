control 'SV-226972' do
  title 'Management Information Base (MIB) files must have mode 0640 or less permissive.'
  desc 'The ability to read the MIB file could impart special knowledge to an intruder or malicious user about the ability to extract compromising information about the system or network.'
  desc 'check', "Check the modes for all Management Information Base (MIB) files on the system.

# find /etc/sma/snmp/ /etc/snmp/conf/ /var/sma_snmp/ /usr/sfw/lib/sma_snmp/ -type f | grep -i mib | egrep -v '\\.conf$' | xargs ls -lL

If any file is returned that does not have mode 0640 or less permissive, this is a finding."
  desc 'fix', 'Change the mode of MIB files to 0640.

Procedure:
# chmod 0640 <mib file>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29134r485246_chk'
  tag severity: 'medium'
  tag gid: 'V-226972'
  tag rid: 'SV-226972r854445_rule'
  tag stig_id: 'GEN005340'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29122r485247_fix'
  tag 'documentable'
  tag legacy: ['V-995', 'SV-40817']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
