control 'SV-217063' do
  title 'The Juniper MPLS router must be configured to use its loopback address as the source address for LDP peering sessions.'
  desc "Using a loopback address as the source address offers a multitude of uses for security, access, management, and scalability of backbone routers. It is easier to construct appropriate ingress filters for router management plane traffic destined to the network management subnet since the source addresses will be from the range used for loopback interfaces instead of from a larger range of addresses used for physical interfaces. Log information recorded by authentication and syslog servers will record the router's loopback address instead of the numerous physical interface addresses."
  desc 'check', 'Review the router configuration to determine if it is compliant with this requirement.

Verify that a loopback address has been configured as shown in the following example:

}
interfaces {
    …
    …
    …
    }
    lo0 {
        unit 0 {
            family inet {
                address 2.2.2.2/32;
            }
        }
    }
}

By default, routers will use its loopback address for LDP peering. If an address has not be configured on the loopback interface, it will use its physical interface connecting to the LDP peer. If the router-id command is specified that overrides this default behavior, verify that it is the IP address of the designated loopback interface as shown in the example below.

}
routing-options {
    router-id 2.2.2.2;
    autonomous-system 5;
}

If the router is not configured do use its loopback address for LDP peering, this is a finding.'
  desc 'fix', 'Configure the router to use their loopback address as the source address for LDP peering sessions. As noted in the check content, the default behavior is to use its loopback address. However, if a router ID is configured, ensure it matches the address of the loopback address as shown in the example below.

[edit routing-options]
set router-id 2.2.2.2'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18292r297057_chk'
  tag severity: 'low'
  tag gid: 'V-217063'
  tag rid: 'SV-217063r639663_rule'
  tag stig_id: 'JUNI-RT-000570'
  tag gtitle: 'SRG-NET-000512-RTR-000002'
  tag fix_id: 'F-18290r297058_fix'
  tag 'documentable'
  tag legacy: ['V-90909', 'SV-101119']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
