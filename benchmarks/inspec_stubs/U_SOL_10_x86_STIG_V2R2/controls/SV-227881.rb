control 'SV-227881' do
  title 'The snmpd.conf files must be owned by root.'
  desc 'The snmpd.conf files contain authenticators and must be protected from unauthorized access and modification.  If the files are not owned by root, they may be subject to access and modification from unauthorized users.'
  desc 'check', 'Determine the owner of the SNMP configuration files. 

Procedure:

# ls -lL /etc/sma/snmp/snmpd.conf /etc/snmp/conf/snmpd.conf /var/sma_snmp/snmpd.conf /usr/sfw/lib/sma_snmp/snmpd.conf

If the snmpd.conf files are not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the snmpd.conf file to root.

Procedure:
# chown root <snmpd.conf file>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30043r490039_chk'
  tag severity: 'medium'
  tag gid: 'V-227881'
  tag rid: 'SV-227881r603266_rule'
  tag stig_id: 'GEN005360'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30031r490040_fix'
  tag 'documentable'
  tag legacy: ['V-12019', 'SV-40274']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
