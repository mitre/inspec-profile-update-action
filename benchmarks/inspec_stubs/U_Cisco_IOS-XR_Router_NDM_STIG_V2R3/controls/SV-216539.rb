control 'SV-216539' do
  title 'The Cisco router must be configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm.'
  desc 'Without the strong encryption that is provided by the SNMP Version 3 User-based Security Model (USM), an unauthorized user can gain access to network management information that can be used to create a network outage.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the example below.

snmp-server host x.x.x.x traps version 3 auth V3USER
snmp-server user V3USER V3GROUP v3 auth sha encrypted 110B1607150B
snmp-server view V3READ iso included
snmp-server view V3WRITE iso included
snmp-server group V3GROUP v3 auth read V3READ write V3WRITE

If the Cisco router is not configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm, this is a finding.'
  desc 'fix', 'Configure the Cisco router to encrypt SNMP messages using a FIPS 140-2 approved algorithm as shown in the example below.

RP/0/0/CPU0:R3(config)#snmp-server group V3GROUP v3 auth read V3READ write V3WRITE
RP/0/0/CPU0:R3(config)#snmp-server user V3USER V3GROUP v3 auth sha xxxxxx priv aes 256 xxxxxx
RP/0/0/CPU0:R3(config)#snmp-server view V3READ iso included
RP/0/0/CPU0:R3(config)#snmp-server view V3WRITE iso included
RP/0/0/CPU0:R3(config)#snmp-server host x.x.x.x version 3 auth V3USER'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17774r288303_chk'
  tag severity: 'medium'
  tag gid: 'V-216539'
  tag rid: 'SV-216539r879768_rule'
  tag stig_id: 'CISC-ND-001140'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-17771r288304_fix'
  tag 'documentable'
  tag legacy: ['SV-105603', 'V-96465']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
