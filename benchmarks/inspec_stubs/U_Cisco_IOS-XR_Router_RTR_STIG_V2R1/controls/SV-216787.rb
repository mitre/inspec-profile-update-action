control 'SV-216787' do
  title 'The Cisco MPLS router must be configured to use its loopback address as the source address for LDP peering sessions.'
  desc "Using a loopback address as the source address offers a multitude of uses for security, access, management, and scalability of backbone routers. It is easier to construct appropriate ingress filters for router management plane traffic destined to the network management subnet since the source addresses will be from the range used for loopback interfaces instead of from a larger range of addresses used for physical interfaces. Log information recorded by authentication and syslog servers will record the router's loopback address instead of the numerous physical interface addresses."
  desc 'check', 'Review the router configuration to determine if it is compliant with this requirement.

Verify that a loopback address has been configured as shown in the following example:

interface Loopback0
 ip address 10.1.1.1 255.255.255.255

By default, routers will use its loopback address for LDP peering. If an address has not be configured on the loopback interface, it will use its physical interface connecting to the LDP peer. If the router-id command is specified that overrides this default behavior, verify that it is the IP address of the designated loopback interface as shown in the example below.

mpls ldp
 router-id 10.1.1.1

If the router is not configured do use its loopback address for LDP peering, this is a finding.'
  desc 'fix', 'Configure the router to use their loopback address as the source address for LDP peering sessions. As noted in the check content, the default behavior is to use its loopback address. 

RP/0/0/CPU0:R3(config)#mpls ldp router-id 10.1.1.1'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18019r288738_chk'
  tag severity: 'low'
  tag gid: 'V-216787'
  tag rid: 'SV-216787r531087_rule'
  tag stig_id: 'CISC-RT-000590'
  tag gtitle: 'SRG-NET-000512-RTR-000002'
  tag fix_id: 'F-18017r288739_fix'
  tag 'documentable'
  tag legacy: ['SV-105919', 'V-96781']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
