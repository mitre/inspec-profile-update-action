control 'SV-12520' do
  title 'The snmpd.conf file must be owned by bin.'
  desc 'The snmpd.conf file contains authenticators and must be protected from unauthorized access and modification.  If the file is not owned by bin, it may be subject to access and modification from unauthorized users.'
  desc 'check', 'Determine the owner of the SNMP configuration file.  Consult vendor documentation to determine the location and name of the file.  

Procedure:
# find / -name snmpd.conf
# ls -lL <snmpd.conf>

If the snmpd.conf file is not owned by bin, this is a finding.'
  desc 'fix', 'Change the owner of the snmpd.conf file to bin.

Procedure:
# chown bin <snmpd.conf file>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-7982r2_chk'
  tag severity: 'medium'
  tag gid: 'V-12019'
  tag rid: 'SV-12520r3_rule'
  tag stig_id: 'GEN005360'
  tag gtitle: 'GEN005360'
  tag fix_id: 'F-11278r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
