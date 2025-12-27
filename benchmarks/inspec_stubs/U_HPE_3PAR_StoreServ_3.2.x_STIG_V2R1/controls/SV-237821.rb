control 'SV-237821' do
  title 'The SNMP service on the storage system must use only SNMPv3 or its successors.'
  desc 'SNMP Versions 1 and 2 are not considered secure. Without the strong authentication and privacy provided by the SNMP Version 3 User-based Security Model (USM), an attacker or other unauthorized users may gain access to detailed system management information and use the information to launch attacks against the system.'
  desc 'check', 'Verify that SNMPv3 is enabled by entering the command: 

cli% showsnmpmgr
HostIP Port SNMPVersion User
<IP address of SNMP manager> 162 3 <username>

If the SNMPVersion is not 3, this is a finding.'
  desc 'fix', 'Configure the OS to use SNMPv3 by entering the command:

cli% setsnmpmgr -snmpuser 3parsnmpuser -pw <password> -version 3 <IP address of SNMP manager>'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.2.x'
  tag check_id: 'C-41031r647870_chk'
  tag severity: 'medium'
  tag gid: 'V-237821'
  tag rid: 'SV-237821r647872_rule'
  tag stig_id: 'HP3P-32-001303'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-40990r647871_fix'
  tag 'documentable'
  tag legacy: ['SV-85117', 'V-70495']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
