control 'SV-216991' do
  title 'The Cisco BGP router must be configured to enable the Generalized TTL Security Mechanism (GTSM).'
  desc "As described in RFC 3682, GTSM is designed to protect a router's IP-based control plane from DoS attacks. Many attacks focused on CPU load and line-card overload can be prevented by implementing GTSM on all Exterior Border Gateway Protocol speaking routers. 

GTSM is based on the fact that the vast majority of control plane peering is established between adjacent routers; that is, the Exterior Border Gateway Protocol peers are either between connecting interfaces or between loopback interfaces. Since TTL spoofing is considered nearly impossible, a mechanism based on an expected TTL value provides a simple and reasonably robust defense from infrastructure attacks based on forged control plane traffic."
  desc 'check', 'Review the BGP configuration to verify that TTL security has been configured for each external neighbor as shown in the example below.

router bgp xx
 no synchronization
 bgp log-neighbor-changes
 neighbor x.1.1.9 remote-as yy
 neighbor x.1.1.9 password xxxxxxxx
 neighbor x.1.1.9 ttl-security hops 1
 neighbor x.2.1.7 remote-as zz
 neighbor x.2.1.7 password xxxxxxxx
 neighbor x.2.1.7 ttl-security hops 1

If the router is not configured to use GTSM for all Exterior Border Gateway Protocol peering sessions, this is a finding.'
  desc 'fix', 'Configure TTL security on all external BGP neighbors as shown in the example below.

R1(config)#router bgp xx
R1(config-router)#neighbor x.1.1.9 ttl-security hops 1
R1(config-router)#neighbor x.2.1.7 ttl-security hops 1'
  impact 0.3
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-18221r287301_chk'
  tag severity: 'low'
  tag gid: 'V-216991'
  tag rid: 'SV-216991r531085_rule'
  tag stig_id: 'CISC-RT-000470'
  tag gtitle: 'SRG-NET-000362-RTR-000124'
  tag fix_id: 'F-18219r287302_fix'
  tag 'documentable'
  tag legacy: ['V-96591', 'SV-105729']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
