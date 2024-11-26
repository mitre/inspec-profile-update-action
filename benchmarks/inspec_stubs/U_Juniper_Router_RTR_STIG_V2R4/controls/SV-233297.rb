control 'SV-233297' do
  title 'The Juniper perimeter router must be configured to drop IPv6 packets containing an extension header with the Endpoint Identification option.'
  desc 'The optional and extensible natures of the IPv6 extension headers require higher scrutiny since many implementations do not always drop packets with headers that it cannot recognize, and hence could cause a Denial-of-Service on the target device. In addition, the type, length, value (TLV) formatting provides the ability for headers to be very large. This option type is associated with the Nimrod Routing system and has no defining RFC document.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration and determine if filters are bound to the applicable interfaces to drop all inbound IPv6 packets containing an option type values of 0x8A (Endpoint Identification) regardless of whether it appears in a Hop-by-Hop or Destination Option header.  

The following example will block IPv6 packet containing either a Hop-by-Hop or Destination Option header: 

    family inet6 {
        filter IPV6-INGRESS-FILTER {
            term HOP_BY_HOP_HEADER {
                from {
                    next-header hop-by-hop;
                }
                then {
                    syslog;
                    discard;
                }
            }
            term DEST_ OPT_HEADER {
                from {
                    next-header dstops;
                }
                then {
                    syslog;
                    discard;
                }
            }
            term ALLOW_TCP_ESTABLISHED {
                from {
                    next-header tcp;
                    tcp-established;
                }
                then accept;
            }
            term DENY_BY_DEFAULT {
                then {
                    syslog;
                    discard;
                }
            }
        }
    }
}


Note: Currently JUNOS has no method to filter option type within either Hop-by-Hop or Destination Option header. Hence, all packets with a Hop-by-Hop or Destination Option headers must be dropped.

If the router is not configured to drop IPv6 packets containing an extension header with the Endpoint Identification option, this is a finding.'
  desc 'fix', 'Step 1: Configure a filter to block packets with either a Hop-by-Hop or Destination Option header as shown in the example.

user@R1# edit firewall family inet6
user@R1# edit filter IPV6-INGRESS-FILTER
user@R1# set term HOP_BY_HOP_HEADER from next-header hop-by-hop
user@R1# set term HOP_BY_HOP_HEADER then discard syslog
user@R1# set term DEST_ OPT_HEADER from next-header dstops
user@R1# set term DEST_ OPT_HEADER then discard syslog
user@R1# top

Step 2: Apply the filter inbound on all external IPv6-enabled interfaces.

user@R1# edit interfaces ge-0/0/0 unit 0 family inet6
user@R1# set filter input IPV6-INGRESS-FILTER
user@R1# commit'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-36232r639654_chk'
  tag severity: 'medium'
  tag gid: 'V-233297'
  tag rid: 'SV-233297r604135_rule'
  tag stig_id: 'JUNI-RT-000385'
  tag gtitle: 'SRG-NET-000364-RTR-000204'
  tag fix_id: 'F-36201r639655_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
