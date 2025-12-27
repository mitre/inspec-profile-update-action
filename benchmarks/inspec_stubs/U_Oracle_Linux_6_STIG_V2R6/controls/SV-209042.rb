control 'SV-209042' do
  title 'The snmpd service must use only SNMP protocol version 3 or newer.'
  desc 'Earlier versions of SNMP are considered insecure, as they potentially allow unauthorized access to detailed system management information.'
  desc 'check', "To ensure only SNMPv3 or newer is used, run the following command: 

# grep 'v1\\|v2c\\|com2sec' /etc/snmp/snmpd.conf | grep -v '^#'

There should be no output. 
If there is output, this is a finding."
  desc 'fix', 'Edit "/etc/snmp/snmpd.conf", removing any references to "v1", "v2c", or "com2sec". Upon doing that, restart the SNMP service: 

# service snmpd restart'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9295r357911_chk'
  tag severity: 'medium'
  tag gid: 'V-209042'
  tag rid: 'SV-209042r793763_rule'
  tag stig_id: 'OL6-00-000340'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9295r357912_fix'
  tag 'documentable'
  tag legacy: ['SV-64923', 'V-50717']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
