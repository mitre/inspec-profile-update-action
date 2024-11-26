control 'SV-223012' do
  title 'The firewall must be configured to inspect all inbound and outbound IPv6 traffic for unknown or out-of-order extension headers.'
  desc 'IPv6 packets with unknown extension headers as well as out-of-order headers can create denial-of-service attacks for other networking components as well as host devices. IPv6 inspection can check conformance to RFC 2460 enforcing the order extension headers. While routers only need to examine the IPv6 destination address and the Hop-by-Hop Options header, firewalls  should must recognize and parse through all existing extension headers since the upper-layer protocol information reside in the last header. An attacker is able to chain lots of extension headers in order to pass firewall- & intrusion detections. An attacker can cause a denial of service if an intermediary device or destination host is not capable of processing an extensive or out-of-order chaine of extension headers. Hence it is imperative, that the firewall is configured to drop packets with unknown or out-of-order headers.'
  desc 'check', 'Review the firewall configuration to verify that IPv6 inspection is being performed on all interfaces.
If the firewall is not configujred to inspect all inbound and outbound IPv6 traffic for unknown or out-of-order extension headers, this is a finding.'
  desc 'fix', 'Configure the firewall to inspect all inbound and outbound traffic at the application layer.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-24684r457851_chk'
  tag severity: 'medium'
  tag gid: 'V-223012'
  tag rid: 'SV-223012r604133_rule'
  tag stig_id: 'SRG-NET-000364-FW-000041'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-24673r457853_fix'
  tag 'documentable'
  tag legacy: ['SV-110209', 'V-101105']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
