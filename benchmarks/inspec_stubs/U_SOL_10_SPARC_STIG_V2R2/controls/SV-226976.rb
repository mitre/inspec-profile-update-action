control 'SV-226976' do
  title 'The snmpd.conf file must not have an extended ACL.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.'
  desc 'check', 'Check the permissions of the SNMP configuration files.
# ls -lL/etc/sma/snmp/snmpd.conf /var/sma_snmp/snmpd.conf /etc/snmp/conf/snmpd.conf /usr/sfw/lib/sma_snmp/snmpd.conf
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the files.
# chmod A- /etc/sma/snmp/snmpd.conf /var/sma_snmp/snmpd.conf /etc/snmp/conf/snmpd.conf /usr/sfw/lib/sma_snmp/snmpd.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29138r485258_chk'
  tag severity: 'medium'
  tag gid: 'V-226976'
  tag rid: 'SV-226976r603265_rule'
  tag stig_id: 'GEN005375'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29126r485259_fix'
  tag 'documentable'
  tag legacy: ['V-22452', 'SV-26737']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
