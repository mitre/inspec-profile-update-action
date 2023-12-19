control 'SV-75379' do
  title 'The Arista Multilayer Switch must ensure all Exterior Border Gateway Protocol (eBGP) routers are configured to use Generalized TTL Security Mechanism (GTSM) or are configured to meet RFC3682.'
  desc "As described in RFC 3682, Generalized TTL Security Mechanism (GTSM) is designed to protect a router's IP-based control plane from DoS attacks. Many attacks focused on CPU load and line-card overload can be prevented by implementing GTSM on all Exterior Border Gateway Protocol-speaking routers. GTSM is based on the fact that the vast majority of control plane peering is established between adjacent routers; that is, the Exterior Border Gateway Protocol peers are either between connecting interfaces or between loopback interfaces. Since TTL spoofing is considered nearly impossible, a mechanism based on an expected TTL value provides a simple and reasonably robust defense from infrastructure attacks based on forged control plane traffic."
  desc 'check', %q(Review the router configuration.

If it is not configured to use Generalized TTL Security Mechanism (GTSM) or is not configured to provide equivalent functionality as per RFC3682 for all Exterior Border Gateway Protocol peering sessions, this is a finding.

The Arista MLS does not have a command to enable GTSM. Instead, any EBGP neighbor statement must include the "ebgp-multihop [hop]" configuration statement, viewable in the "router bgp [AS number]" section of the running config. For adjacent peers, this number must be 255.

Additionally, the control-plane ACL must have a statement that matches against the neighbor's correct TTL to allow inbound packets to the Switch. The neighbor TTL must be 255 for an adjacent peer or the result of 255-(number of hops) for a multihop peer.)
  desc 'fix', 'Configure all Exterior Border Gateway Protocol peering sessions to use Generalized TTL Security Mechanism (GTSM) or an equivalent configuration as per RFC3682.

For adjacent EBGP neighbors, under the router configuration section, enter:

config
router bgp [AS number]
neighbor [address] ebgp-multihop 255
exit
ip access-list [name]
permit tcp [src address/mask] [dst address/mask] eq bgp ttl eq 255 log
exit
control-plane
ip access-group [name] [direction]'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61867r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60921'
  tag rid: 'SV-75379r1_rule'
  tag stig_id: 'AMLS-L3-000260'
  tag gtitle: 'SRG-NET-000191-RTR-000081'
  tag fix_id: 'F-66633r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
