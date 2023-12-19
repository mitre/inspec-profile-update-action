control 'SV-256049' do
  title 'The MPLS router must be configured to use its loopback address as the source address for LDP peering sessions.'
  desc "Using a loopback address as the source address offers a multitude of uses for security, access, management, and scalability of backbone routers. It is easier to construct appropriate ingress filters for router management plane traffic destined to the network management subnet since the source addresses will be from the range used for loopback interfaces instead of from a larger range of addresses used for physical interfaces. Log information recorded by authentication and syslog servers will record the router's loopback address instead of the numerous physical interface addresses."
  desc 'check', 'Review the Arista router configuration to determine if it uses its loopback address as the source address for LDP peering sessions.

To verify a loopback address has been configured as shown in the following example, execute the command "sh run int loopback YY".

interface loopback 0
  ip address 10.1.1.1/32

An MPLS router will use the LDP router ID as the source address for LDP hellos and when establishing TCP sessions with LDP peers; hence, it is necessary to verify the LDP router ID is the same as the loopback address. By default, routers will assign the LDP router ID using the highest IP address on the router, with preference given to loopback addresses. If the router-id command is specified that overrides this default behavior, verify it is the IP address of the designated loopback interface.

mpls ldp
   router-id interface Loopback0
   no shutdown

If the Arista router is not configured to use its loopback address for LDP peering, this is a finding.'
  desc 'fix', 'Configure the Arista MPLS routers to use their loopback address as the source address for LDP peering sessions.

Step 1: Configure the loopback interface.

LEAF-1A(config)#interface Loopback0
LEAF-1A(config-if-Lo0)#ip address 10.1.1.1/32

Step 2: Configure the loopback interface as LDP router-id.

LEAF-1A(config)#mpls ldp
LEAF-1A(config-mpls-ldp)#router-id interface Loopback0
LEAF-1A(config-mpls-ldp)#no shutdown'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59725r882487_chk'
  tag severity: 'low'
  tag gid: 'V-256049'
  tag rid: 'SV-256049r882489_rule'
  tag stig_id: 'ARST-RT-000700'
  tag gtitle: 'SRG-NET-000512-RTR-000002'
  tag fix_id: 'F-59668r882488_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
