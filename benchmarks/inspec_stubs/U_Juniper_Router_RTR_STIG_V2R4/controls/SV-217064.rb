control 'SV-217064' do
  title 'The Juniper MPLS router must be configured to synchronize IGP and LDP to minimize packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.'
  desc 'Packet loss can occur when an IGP adjacency is established and the router begins forwarding packets using the new adjacency before the LDP label exchange completes between the peers on that link. Packet loss can also occur if an LDP session closes and the router continues to forward traffic using the link associated with the LDP peer rather than an alternate pathway with a fully synchronized LDP session. The MPLS LDP-IGP Synchronization feature provides a means to synchronize LDP with OSPF or IS-IS to minimize MPLS packet loss. When an IGP adjacency is established on a link but LDP-IGP synchronization is not yet achieved or is lost, the IGP will advertise the max-metric on that link.'
  desc 'check', 'Review the router OSPF or IS-IS configuration and verify that LDP will synchronize with the link-state routing protocol as shown in the example below.

OSPF Example:

protocols {
    mpls {
        interface ge-0/0/0.0;
    }
    …
    …
    …
    ospf {
        export REDISTRIBUTE;
        area 0.0.0.0 {
            interface ge-0/0/0.0 {
                ldp-synchronization {
                    hold-time 10;
                }
        …
        …
        …
        }
    }
    ldp {
        interface ge-0/0/0.0;
    }
}

IS-IS Example:

protocols {
    mpls {
        interface ge-0/0/0.0;
    }
    …
    …
    …
    isis {
        level 1 authentication-key-chain ISIS_KEY;
        level 2 authentication-key-chain ISIS_KEY;
        interface ge-0/0/0.0 {
            ldp-synchronization {
                hold-time 10;
            }
        …
        …
        …
        }
    }
    ldp {
        interface ge-0/0/0.0;
    }
}

If the router is not configured to synchronize IGP and LDP, this is a finding.'
  desc 'fix', 'Configure the MPLS router to synchronize IGP and LDP, minimizing packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.

[edit protocols ospf area 0.0.0.0]
set interface ge-0/0/0.0 ldp-synchronization hold-time 10

[edit protocols isis]
set interface ge-0/0/0.0 ldp-synchronization hold-time 10

Note: The hold-time is the amount of time (in seconds) the routing device advertises the maximum cost metric for a link that is not fully operational. Default is infinity.'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18293r297060_chk'
  tag severity: 'low'
  tag gid: 'V-217064'
  tag rid: 'SV-217064r604135_rule'
  tag stig_id: 'JUNI-RT-000580'
  tag gtitle: 'SRG-NET-000512-RTR-000003'
  tag fix_id: 'F-18291r297061_fix'
  tag 'documentable'
  tag legacy: ['SV-101121', 'V-90911']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
