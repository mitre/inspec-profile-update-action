control 'SV-254053' do
  title 'The Juniper perimeter router must be configured to drop fragmented IPv6 packets where the first fragment does not include the entire IPv6 header chain.'
  desc 'One of the fragmentation weaknesses known in IPv6 is the "undetermined transport" packet, which is the first fragment where the entire IPv6 header chain is not included. Fragmenting IPv6 datagrams and not including the upper-layer header makes it difficult to identify the traffic. 

RFC7112 and RFC8200 require the entire IPv6 header chain be present in the first fragment and defines the header chain as:
"The IPv6 Header Chain contains an initial IPv6 header, zero or more IPv6 Extension Headers, and optionally, a single upper-layer header. If an upper-layer header is present, it terminates the header chain; otherwise, the "No Next Header" value (Next Header = 59) terminates it."

Both RFCs consider a second IPv6 header and an ESP header as "upper-layer headers" when determining where the IPv6 header chain terminates.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

There is no check for dropping RFC 7112 nonconformant fragmented IPv6 packets because Juniper EX switches drop these packets without offering or requiring a configurable option in the CLI.

Review the router configuration to determine if it is configured to drop fragmented transit IPv6 traffic.

[edit firewall family inet6]
filter <filter name> {
    term <name> {
        from {
            next-header fragment;
        }
        then {
            syslog;
            discard;
        }
    }
}

Note: Some platforms also support "is-fragment" or "fragment-flags is-fragment" in addition to "next-header fragment" as shown in the example.

If the router is not configured to drop first-fragment IPv6 packets without the entire header chain, this is a finding.'
  desc 'fix', 'Configure the router to drop first-fragment IPv6 packets without the entire header chain.

There is no configurable CLI option to prevent EX devices from dropping nonconformant fragmented IPv6 packets destined to the device.

Configure the router to drop fragmented transit IPv6 packets.

set firewall family inet6 filter <name> term <name> from next-header fragment
set firewall family inet6 filter <name> term <name> then syslog
set firewall family inet6 filter <name> term <name> then discard'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57505r844190_chk'
  tag severity: 'medium'
  tag gid: 'V-254053'
  tag rid: 'SV-254053r844192_rule'
  tag stig_id: 'JUEX-RT-000810'
  tag gtitle: 'SRG-NET-000364-RTR-000200'
  tag fix_id: 'F-57456r844191_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
