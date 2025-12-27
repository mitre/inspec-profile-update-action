control 'SV-85119' do
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
  ref 'DPMS Target HPE 3PAR OS 3.2.2'
  tag check_id: 'C-70897r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70497'
  tag rid: 'SV-85119r1_rule'
  tag stig_id: 'HP3P-32-001305'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-76735r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
