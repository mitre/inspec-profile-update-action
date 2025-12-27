control 'SV-88803' do
  title 'The Cisco IOS XE router must ensure all Exterior Border Gateway Protocol (eBGP) routers are configured to use Generalized TTL Security Mechanism (GTSM).'
  desc "As described in RFC 3682, Generalized TTL Security Mechanism (GTSM) is designed to protect a router's IP-based control plane from DoS attacks. Many attacks focused on CPU load and line-card overload can be prevented by implementing GTSM on all Exterior Border Gateway Protocol speaking routers. GTSM is based on the fact that the vast majority of control plane peering is established between adjacent routers; that is, the Exterior Border Gateway Protocol peers are either between connecting interfaces or between loopback interfaces. Since TTL spoofing is considered nearly impossible, a mechanism based on an expected TTL value provides a simple and reasonably robust defense from infrastructure attacks based on forged control plane traffic."
  desc 'check', 'Review the Cisco IOS XE router configuration and verify that the neighbor command "ttl-security" is configured for all eBGP peering sessions.

The configuration would look similar to the following:

router bgp 100
neighbor 10.1.1.1 remote-as 222
neighbor 10.1.1.1 ttl-security hops 1

If the "ttl-security" command is not configured for all eBGP peering sessions, this is a finding.'
  desc 'fix', 'Configure all eBGP neighbors with GTSM. The configuration would look similar to the following:

router bgp 100
neighbor 10.1.1.1 remote-as 222
neighbor 10.1.1.1 ttl-security hops 1'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE RTR'
  tag check_id: 'C-74215r2_chk'
  tag severity: 'medium'
  tag gid: 'V-74129'
  tag rid: 'SV-88803r2_rule'
  tag stig_id: 'CISR-RT-000018'
  tag gtitle: 'SRG-NET-000191-RTR-000081'
  tag fix_id: 'F-80671r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
