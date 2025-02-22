control 'SV-221021' do
  title 'The Cisco BGP switch must be configured to enable the Generalized TTL Security Mechanism (GTSM).'
  desc "As described in RFC 3682, GTSM is designed to protect a switch's IP-based control plane from DoS attacks. Many attacks focused on CPU load and line-card overload can be prevented by implementing GTSM on all Exterior Border Gateway Protocol-speaking switches. 

GTSM is based on the fact that the vast majority of control plane peering is established between adjacent switches; that is, the Exterior Border Gateway Protocol peers are either between connecting interfaces or between loopback interfaces. Since TTL spoofing is considered nearly impossible, a mechanism based on an expected TTL value provides a simple and reasonably robust defense from infrastructure attacks based on forged control plane traffic."
  desc 'check', 'Review the BGP configuration to verify that TTL security has been configured for each external neighbor as shown in the example below:

router bgp xx
 no synchronization
 bgp log-neighbor-changes
 neighbor x.1.1.9 remote-as yy
 neighbor x.1.1.9 password xxxxxxxx
 neighbor x.1.1.9 ttl-security hops 1
 neighbor x.2.1.7 remote-as zz
 neighbor x.2.1.7 password xxxxxxxx
 neighbor x.2.1.7 ttl-security hops 1

If the switch is not configured to use GTSM for all Exterior Border Gateway Protocol peering sessions, this is a finding.'
  desc 'fix', 'Configure TTL security on all external BGP neighbors as shown in the example below:

SW1(config)#router bgp xx
SW1(config-switch)#neighbor x.1.1.9 ttl-security hops 1
SW1(config-switch)#neighbor x.2.1.7 ttl-security hops 1'
  impact 0.3
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22736r408857_chk'
  tag severity: 'low'
  tag gid: 'V-221021'
  tag rid: 'SV-221021r856414_rule'
  tag stig_id: 'CISC-RT-000470'
  tag gtitle: 'SRG-NET-000362-RTR-000124'
  tag fix_id: 'F-22725r408858_fix'
  tag 'documentable'
  tag legacy: ['SV-110863', 'V-101759']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
