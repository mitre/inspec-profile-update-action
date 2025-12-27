control 'SV-221102' do
  title 'The Cisco BGP switch must be configured to use a unique key for each autonomous system (AS) that it peers with.'
  desc 'If the same keys are used between eBGP neighbors, the chance of a hacker compromising any of the BGP sessions increases. It is possible that a malicious user exists in one autonomous system who would know the key used for the eBGP session. This user would then be able to hijack BGP sessions with other trusted neighbors.'
  desc 'check', 'Review the BGP configuration to determine if it is peering with multiple autonomous systems. Interview the ISSM and switch administrator to determine if unique keys are being used. 

router bgp xx
 router-id 10.1.1.1
 neighbor x.1.12.2 remote-as 2
 password 3 7b07d1b3023056a9
 address-family ipv4 unicast
 neighbor x.2.44.4 remote-as xx
 password 3 f07a10cb41db8bb6f8f0a340049a9b02
 address-family ipv4 unicast

If unique keys are not being used, this is a finding.'
  desc 'fix', 'Configure the switch to use unique keys for each AS that it peers with as shown in the example below:

SW1(config)# router bgp xx
SW1(config-router)# neighbor x.1.12.2
SW1(config-router-neighbor)# password yyyyyyyyy
SW1(config-router-neighbor)# exit
SW1(config-router)# neighbor x.2.44.4
SW1(config-router-neighbor)# password zzzzzzzzzz
SW1(config-router-neighbor)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22817r409795_chk'
  tag severity: 'medium'
  tag gid: 'V-221102'
  tag rid: 'SV-221102r856659_rule'
  tag stig_id: 'CISC-RT-000480'
  tag gtitle: 'SRG-NET-000230-RTR-000002'
  tag fix_id: 'F-22806r409796_fix'
  tag 'documentable'
  tag legacy: ['SV-111023', 'V-101919']
  tag cci: ['CCI-002205', 'CCI-000366']
  tag nist: ['AC-4 (17)', 'CM-6 b']
end
