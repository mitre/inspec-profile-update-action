control 'SV-220605' do
  title 'The Cisco switch must be configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm.'
  desc 'Without the strong encryption that is provided by the SNMP Version 3 User-based Security Model (USM), an unauthorized user can gain access to network management information that can be used to create a network outage.'
  desc 'check', 'Review the Cisco switch configuration to verify that it encrypts SNMP messages using a FIPS 140-2 approved algorithm as shown in the example below:

snmp-server group V3GROUP v3 priv read V3READ write V3WRITE
snmp-server view V3READ iso included
snmp-server view V3WRITE iso included
snmp-server host x.x.x.x version 3 auth V3USER

Encryption used by the SNMP users can be viewed via the show snmp user command as shown in the example below:

R4#show snmp user

User name: V3USER
Engine ID: 800000090300C2042B540000
storage-type: nonvolatile active
Authentication Protocol: SHA
Privacy Protocol: AES256
Group-name: V3GROUP

If the Cisco switch is not configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to encrypt SNMP messages using a FIPS 140-2 approved algorithm as shown in the example below:

SW4(config)#snmp-server group V3GROUP v3 priv read V3READ write V3WRITE
SW4(config)#snmp-server user V3USER V3GROUP v3 auth sha xxxxxx priv aes 256 xxxxxx'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22320r507861_chk'
  tag severity: 'medium'
  tag gid: 'V-220605'
  tag rid: 'SV-220605r521267_rule'
  tag stig_id: 'CISC-ND-001140'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-22309r507862_fix'
  tag 'documentable'
  tag legacy: ['SV-110439', 'V-101335']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
