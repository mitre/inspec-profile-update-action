control 'SV-254061' do
  title 'The Juniper MPLS router must be configured to use its loopback address as the source address for LDP peering sessions.'
  desc "Using a loopback address as the source address offers a multitude of uses for security, access, management, and scalability of backbone routers. It is easier to construct appropriate ingress filters for router management plane traffic destined to the network management subnet since the source addresses will be from the range used for loopback interfaces instead of from a larger range of addresses used for physical interfaces. Log information recorded by authentication and syslog servers will record the router's loopback address instead of the numerous physical interface addresses."
  desc 'check', 'Review the router configuration to determine if it uses its loopback address as the source address for LDP peering sessions.

Verify that a loopback address has been configured as shown in the following example:
[edit interfaces]
lo0 {
    unit 0 {
        family inet {
            address <IPv4 address>/32;
        }
        family inet6 {
            address <IPv6 address>/128;
        }
    }
}

An MPLS router will use the LDP router ID as the source address for LDP hellos and when establishing TCP sessions with LDP peers; hence, it is necessary to verify that the LDP router ID is the same as the loopback address. By default, routers will assign the LDP router ID using the highest IP address on the router, with preference given to loopback addresses. If the router-id command is specified that overrides this default behavior, verify that it is the IP address of the designated loopback interface.

[edit routing-options]
router-id <lo0 address>;

If the router is not configured do use its loopback address for LDP peering, this is a finding.'
  desc 'fix', 'Configure MPLS routers to use their loopback address as the source address for LDP peering sessions.

set interfaces lo0 unit 0 family inet <IPv4 address>/32
set interfaces lo0 unit 0 family inet6 <IPv6 address>/128

set routing-options router-id <lo0 address>'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57513r844214_chk'
  tag severity: 'low'
  tag gid: 'V-254061'
  tag rid: 'SV-254061r844216_rule'
  tag stig_id: 'JUEX-RT-000890'
  tag gtitle: 'SRG-NET-000512-RTR-000002'
  tag fix_id: 'F-57464r844215_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
