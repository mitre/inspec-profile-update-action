control 'SV-239870' do
  title 'The Cisco ASA must be configured to inspect all inbound and outbound IPv6 traffic for unknown or out-of-order extension headers.'
  desc 'IPv6 packets with unknown extension headers as well as out-of-order headers can create Denial-of-Service attacks for other networking components as well as host devices. IPv6 inspection can check conformance to RFC 2460 enforcing the order extension headers. While routers only need to examine the IPv6 destination address and the Hop-by-Hop Options header, firewalls must recognize and parse through all existing extension headers since the upper-layer protocol information resides in the last header. An attacker is able to chain many extension headers in order to pass firewall and intrusion detections. An attacker can cause a denial of service if an intermediary device or destination host is not capable of processing an extensive or out-of-order chain of extension headers. Hence, it is imperative the firewall is configured to drop packets with unknown or out-of-order headers.'
  desc 'check', 'Review the firewall configuration to verify that IPv6 inspection is being performed on all interfaces.

Step 1: Verify that the inspect ipv6 command is configured under the global policy map as shown in the example below.

policy-map global_policy
 class inspection_default
  …
  …
  …
  inspect ipv6 IPV6_MAP

Step 2: If a policy map is specified for the inspect ipv6 command, verify the parameters command has been configured. Also verify that the “no verify-header order” and “no verify-header type” sub-command are not configured under the parameters command.

policy-map type inspect ipv6 IPV6_MAP
 parameters
 match header hop-by-hop
  drop log
match header routing-type eq 0
  drop log
match header routing-type eq 1
  drop log
match header routing-type range 3 255
  drop log
 match header destination-option
  drop log

Note: If policy map is not specified for the inspect ipv6 command, the default IPv6 inspection policy map is used and the following actions are taken:

1. Allows only known IPv6 extension headers. Non-conforming packets are dropped and logged.
2. Enforces the order of IPv6 extension headers as defined in the RFC 2460 specification. Non-conforming packets are dropped and logged.
3. Drops any packet with a routing type header.

Note: This requirement is not applicable if IPv6 is not enabled on any interfaces.

If the firewall is not configured to inspect all inbound and outbound IPv6 traffic for unknown or out-of-order extension headers, this is a finding.'
  desc 'fix', 'Configure the firewall to inspect all inbound and outbound IPv6 traffic for unknown or out-of-order extension headers.

Step 1 (optional): Configure an IPv6 inspect policy map.

ASA(config)# policy-map type inspect  ipv6 IPV6_MAP 
ASA(config-pmap)# parameters
ASA(config-pmap-p)# verify-header type 
ASA(config-pmap-p)# verify-header order
ASA(config-pmap-p)# exit
ASA(config-pmap)# match header hop-by-hop 
ASA(config-pmap-c)# drop log 
ASA(config-pmap-c)# exit 
ASA(config-pmap)# match header routing-type eq 0
ASA(config-pmap-c)# drop log 
ASA(config-pmap-c)# exit
ASA(config-pmap)# match header routing-type eq 1
ASA(config-pmap-c)# drop log 
ASA(config-pmap-c)# exit
ASA(config-pmap)# match header routing-type range 3 255
ASA(config-pmap-c)# drop log 
ASA(config-pmap-c)# exit

Note: The verify-header type and verify-header order are enabled by default when the parameters command is configured.

Step 2: Include the inspect ipv6 command in the global policy-map as shown in the example below.

ASA(config)# policy-map global_policy
ASA(config-pmap)# class inspection_default
ASA(config-pmap-c)# inspect ipv6
ASA(config-pmap-c)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43103r665894_chk'
  tag severity: 'medium'
  tag gid: 'V-239870'
  tag rid: 'SV-239870r665896_rule'
  tag stig_id: 'CASA-FW-000280'
  tag gtitle: 'SRG-NET-000364-FW-000041'
  tag fix_id: 'F-43062r665895_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
