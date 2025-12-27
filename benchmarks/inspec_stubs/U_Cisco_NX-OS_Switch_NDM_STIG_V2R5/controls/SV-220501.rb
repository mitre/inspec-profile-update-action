control 'SV-220501' do
  title 'The Cisco switch must be configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm.'
  desc 'Without the strong encryption that is provided by the SNMP Version 3 User-based Security Model (USM), an unauthorized user can gain access to network management information that can be used to create a network outage.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in the example below:

snmp-server user NETOPS auth sha 5Er23@#as178 priv aes-128 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

Encryption used by the SNMP users can be viewed via the show snmp user command as shown in the example below:

SW1# show snmp user
______________________________________________________________
 SNMP USERS 
______________________________________________________________

User Auth Priv(enforce) Groups acl_filter 
____ ____ ___________ ______ __________ 
NETOPS sha aes-128 network-operator 

If the Cisco switch is not configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to encrypt SNMP messages using a FIPS 140-2 approved algorithm as shown in the example below:

SW1(config)# snmp-server user NETOPS auth sha xxxxxxxxxxxxx priv aes-128 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22216r539224_chk'
  tag severity: 'medium'
  tag gid: 'V-220501'
  tag rid: 'SV-220501r879768_rule'
  tag stig_id: 'CISC-ND-001140'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-22205r539225_fix'
  tag 'documentable'
  tag legacy: ['SV-110651', 'V-101547']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
