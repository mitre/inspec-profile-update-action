control 'SV-80623' do
  title 'The HP FlexFabric Switch must ensure all Exterior Border Gateway Protocol (eBGP) HP FlexFabric Switches are configured to use Generalized TTL Security Mechanism (GTSM).'
  desc "As described in RFC 3682, GTSM is designed to protect a router's IP-based control plane from DoS attacks. Many attacks focused on CPU load and line-card overload can be prevented by implementing GTSM on all eBGP speaking routers. GTSM is based on the fact that the vast majority of control plane peering is established between adjacent routers; that is, the eBGP peers are either between connecting interfaces or between loopback interfaces. Since TTL spoofing is considered nearly impossible, a mechanism based on an expected TTL value provides a simple and reasonably robust defense from infrastructure attacks based on forged control plane traffic."
  desc 'check', 'Review the HP FlexFabric Switch configuration.

If the HP FlexFabric Switch  is not configured to use GTSM for all eBGP peering sessions, this is a finding.

[HP] display current-configuration
#
bgp 2000
 graceful-restart
 peer 10.10.10.1 as-number 2000
 peer 10.10.10.1 ttl-security hops 254
 peer 201.6.1.193 as-number 1473
 peer 201.6.1.193 route-update-interval 0
 peer 201.6.1.193 password cipher $c$3$6jyBDW1nVs/F0410R54zhmhD1HYhs5I=
 peer 2115:B:1::C1 as-number 1473
 peer 2115:B:1::C1 route-update-interval 0'
  desc 'fix', 'Configure all eBGP peering sessions to use GTSM.

[HP] bgp 2000
[HP-bgp] peer 192.178.19.1 as-number 2100
[HP-bgp] peer 192.178.19.1 ttl-security hops 254'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66779r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66133'
  tag rid: 'SV-80623r1_rule'
  tag stig_id: 'HFFS-RT-000023'
  tag gtitle: 'SRG-NET-000191-RTR-000081'
  tag fix_id: 'F-72209r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
