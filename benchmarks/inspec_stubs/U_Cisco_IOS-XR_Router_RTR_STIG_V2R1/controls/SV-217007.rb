control 'SV-217007' do
  title 'The Cisco BGP router must be configured to enable the Generalized TTL Security Mechanism (GTSM).'
  desc "As described in RFC 3682, GTSM is designed to protect a router's IP-based control plane from DoS attacks. Many attacks focused on CPU load and line-card overload can be prevented by implementing GTSM on all Exterior Border Gateway Protocol speaking routers. 

GTSM is based on the fact that the vast majority of control plane peering is established between adjacent routers; that is, the Exterior Border Gateway Protocol peers are either between connecting interfaces or between loopback interfaces. Since TTL spoofing is considered nearly impossible, a mechanism based on an expected TTL value provides a simple and reasonably robust defense from infrastructure attacks based on forged control plane traffic."
  desc 'check', 'Review the BGP configuration to verify that TTL security has been configured for each external neighbor as shown in the example below.

router bgp n
 address-family ipv4 unicast
 !
 neighbor x.1.23.3
  remote-as n
  ttl-security
  address-family ipv4 unicast
  !
 !
!

If the router is not configured to use GTSM for all Exterior Border Gateway Protocol peering sessions, this is a finding.'
  desc 'fix', 'Configure TTL security on all external BGP neighbors as shown in the example below.

RP/0/0/CPU0:R2(config)#router bgp n
RP/0/0/CPU0:R2(config-bgp)#neighbor x.1.23.3   
RP/0/0/CPU0:R2(config-bgp-nbr)#ttl-security'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18237r288861_chk'
  tag severity: 'low'
  tag gid: 'V-217007'
  tag rid: 'SV-217007r531087_rule'
  tag stig_id: 'CISC-RT-000470'
  tag gtitle: 'SRG-NET-000362-RTR-000124'
  tag fix_id: 'F-18235r288862_fix'
  tag 'documentable'
  tag legacy: ['V-96757', 'SV-105895']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
