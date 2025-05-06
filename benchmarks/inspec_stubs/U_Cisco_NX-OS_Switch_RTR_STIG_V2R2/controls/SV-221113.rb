control 'SV-221113' do
  title 'The Cisco MPLS switch must be configured to use its loopback address as the source address for LDP peering sessions.'
  desc "Using a loopback address as the source address offers a multitude of uses for security, access, management, and scalability of backbone switches. It is easier to construct appropriate ingress filters for switch management plane traffic destined to the network management subnet since the source addresses will be from the range used for loopback interfaces instead of from a larger range of addresses used for physical interfaces. Log information recorded by authentication and syslog servers will record the switch's loopback address instead of the numerous physical interface addresses."
  desc 'check', 'Review the switch configuration to determine if it is compliant with this requirement.

Verify that a loopback address has been configured as shown in the following example:

interface loopback0
 ip address 10.1.1.1/32

By default, switches will use its loopback address for LDP peering. If an address has not be configured on the loopback interface, it will use its physical interface connecting to the LDP peer. If the router-id command is specified that overrides this default behavior, verify that it is a loopback interface as shown in the example below:

mpls ldp configuration
 router-id lo0

If the switch is not configured do use its loopback address for LDP peering, this is a finding.'
  desc 'fix', 'Configure the switch to use their loopback address as the source address for LDP peering sessions. As noted in the check content, the default behavior is to use its loopback address. 

SW1(config)# mpls ldp configuration
SW1(config-ldp)# router-id lo0'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22828r409828_chk'
  tag severity: 'low'
  tag gid: 'V-221113'
  tag rid: 'SV-221113r622190_rule'
  tag stig_id: 'CISC-RT-000590'
  tag gtitle: 'SRG-NET-000512-RTR-000002'
  tag fix_id: 'F-22817r409829_fix'
  tag 'documentable'
  tag legacy: ['SV-111045', 'V-101941']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
