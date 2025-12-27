control 'SV-217008' do
  title 'The Cisco BGP router must be configured to use a unique key for each autonomous system (AS) that it peers with.'
  desc 'If the same keys are used between eBGP neighbors, the chance of a hacker compromising any of the BGP sessions increases. It is possible that a malicious user exists in one autonomous system who would know the key used for the eBGP session. This user would then be able to hijack BGP sessions with other trusted neighbors.'
  desc 'check', 'Review the BGP configuration to determine if it is peering with multiple autonomous systems. Interview the ISSM and router administrator to determine if unique keys are being used. 

router bgp n
 address-family ipv4 unicast
 !
 neighbor x.1.23.3
  remote-as y
  keychain YYY_KEY_CHAIN
  ttl-security
  address-family ipv4 unicast
  !
 !
 neighbor x.1.24.4
  remote-as z
  keychain ZZZ_KEY_CHAIN
  ttl-security
  address-family ipv4 unicast
 !
!

If unique keys are not being used, this is a finding.'
  desc 'fix', 'Configure the router to use unique keys for each AS that it peers with as shown in the example below.

RP/0/0/CPU0:R2(config)#router bgp n
RP/0/0/CPU0:R2(config-bgp)#neighbor x.1.23.3
RP/0/0/CPU0:R2(config-bgp-nbr)#keychain YYY_KEY_CHAIN 
RP/0/0/CPU0:R2(config-bgp-nbr)#neighbor x.1.24.4
RP/0/0/CPU0:R2(config-bgp-nbr)#keychain ZZZ_KEY_CHAIN 
RP/0/0/CPU0:R2(config-bgp-nbr)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18238r288864_chk'
  tag severity: 'medium'
  tag gid: 'V-217008'
  tag rid: 'SV-217008r856463_rule'
  tag stig_id: 'CISC-RT-000480'
  tag gtitle: 'SRG-NET-000230-RTR-000002'
  tag fix_id: 'F-18236r288865_fix'
  tag 'documentable'
  tag legacy: ['SV-105897', 'V-96759']
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
