control 'SV-221101' do
  title 'The Cisco BGP switch must be configured to check whether a single-hop eBGP peer is directly connected.'
  desc "As described in RFC 3682, GTSM is designed to protect a switch's IP-based control plane from DoS attacks. Many attacks focused on CPU load and line-card overload can be prevented by implementing GTSM on all Exterior Border Gateway Protocol-speaking switches. 

GTSM is based on the fact that the vast majority of control plane peering is established between adjacent switches; that is, the Exterior Border Gateway Protocol peers are either between connecting interfaces or between loopback interfaces. Since TTL spoofing is considered nearly impossible, a mechanism based on an expected TTL value provides a simple and reasonably robust defense from infrastructure attacks based on forged control plane traffic."
  desc 'check', 'Review the BGP configuration to verify that checking whether a single-hop eBGP peer is directly connected. The example below disables this mechanism.

router bgp xx
 router-id 10.1.1.1
 neighbor x.1.12.2 remote-as xx
 disable-connected-check
 address-family ipv4 unicast

Note: BGP triggers a connection check automatically for all eBGP peers that are known to be a single hop away, unless this check is disabled with the disable-connected-check command. BGP does not bring up sessions if the check fails.

If the switch is configured to disable checking whether a single-hop eBGP peer is directly connected, this is a finding.'
  desc 'fix', 'Remove the command that disables checking whether a single-hop eBGP peer is directly connected for all external BGP neighbors as shown in the example below:

SW1(config)# router bgp xx
SW1(config-router)# neighbor x.1.12.2
SW1(config-router-neighbor)# no disable-connected-check 
SW1(config-router-neighbor)# end'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22816r409792_chk'
  tag severity: 'low'
  tag gid: 'V-221101'
  tag rid: 'SV-221101r622190_rule'
  tag stig_id: 'CISC-RT-000470'
  tag gtitle: 'SRG-NET-000362-RTR-000124'
  tag fix_id: 'F-22805r409793_fix'
  tag 'documentable'
  tag legacy: ['SV-111021', 'V-101917']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
