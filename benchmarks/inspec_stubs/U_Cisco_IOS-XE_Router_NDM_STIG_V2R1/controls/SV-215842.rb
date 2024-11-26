control 'SV-215842' do
  title 'The Cisco router must be configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm.'
  desc 'Without the strong encryption that is provided by the SNMP Version 3 User-based Security Model (USM), an unauthorized user can gain access to network management information that can be used to create a network outage.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the example below.

snmp-server group V3GROUP v3 priv read V3READ write V3WRITE
snmp-server view V3READ iso included
snmp-server view V3WRITE iso included
snmp-server host x.x.x.x version 3 auth V3USER

Encryption used by the SNMP users can be viewed via the show snmp user command as shown in the example below.

R4#show snmp user

User name: V3USER
Engine ID: 800000090300C2042B540000
storage-type: nonvolatile active
Authentication Protocol: SHA
Privacy Protocol: AES256
Group-name: V3GROUP

If the Cisco router is not configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm, this is a finding.'
  desc 'fix', 'Configure the Cisco router to encrypt SNMP messages using a FIPS 140-2 approved algorithm as shown in the example below.

R4(config)#snmp-server group V3GROUP v3 priv read V3READ write V3WRITE
R4(config)#snmp-server user V3USER V3GROUP v3 auth sha xxxxxx priv aes 256 xxxxxx'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17081r287565_chk'
  tag severity: 'medium'
  tag gid: 'V-215842'
  tag rid: 'SV-215842r531083_rule'
  tag stig_id: 'CISC-ND-001140'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-17079r287566_fix'
  tag 'documentable'
  tag legacy: ['V-96319', 'SV-105457']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
