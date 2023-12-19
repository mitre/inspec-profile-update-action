control 'SV-237822' do
  title 'The SNMP service on the storage system must require the use of a FIPS 140-2 approved cryptographic hash algorithm as part of its authentication and integrity methods.'
  desc 'The SNMP service must use AES or a FIPS 140-2 approved successor algorithm for protecting the privacy of communications.'
  desc 'check', 'Verify that SNMP encryption uses AES by entering the following command:

cli% showsnmpuser
Username AuthProtocol PrivProtocol
3parsnmpuser HMAC-SHA-96 CFB128-AES-128

If the PrivProtocol in the result is not AES, this is a finding.'
  desc 'fix', 'Configure the storage system to use AES encryption for SNMPv3 by entering the command:

cli% setsnmpmgr -snmpuser 3parsnmpuser -pw <password> -version 3 <IP address of SNMP manager>'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.2.x'
  tag check_id: 'C-41032r647873_chk'
  tag severity: 'medium'
  tag gid: 'V-237822'
  tag rid: 'SV-237822r647875_rule'
  tag stig_id: 'HP3P-32-001305'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-40991r647874_fix'
  tag 'documentable'
  tag legacy: ['SV-85119', 'V-70497']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
