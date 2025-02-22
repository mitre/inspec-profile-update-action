control 'SV-218585' do
  title 'The snmpd.conf file must be owned by root.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.  If the file is not owned by root, it may be subject to access and modification from unauthorized users.'
  desc 'check', 'Determine the owner of the SNMP configuration file.

Procedure:
Find the snmpd.conf file. The default install location is /etc/snmp/snmpd.conf but may be different depending on the SNMP agent installed.

# find / -name snmpd.conf 
# ls -lL <snmpd.conf>

If the snmpd.conf file is not owned by root, this is a finding.'
  desc 'fix', 'Change the owner of the snmpd.conf file to root.

Procedure:
# chown root <snmpd.conf file>'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20060r555953_chk'
  tag severity: 'medium'
  tag gid: 'V-218585'
  tag rid: 'SV-218585r603259_rule'
  tag stig_id: 'GEN005360'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20058r555954_fix'
  tag 'documentable'
  tag legacy: ['V-12019', 'SV-63443']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
