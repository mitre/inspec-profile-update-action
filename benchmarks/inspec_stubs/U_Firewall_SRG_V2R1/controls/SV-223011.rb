control 'SV-223011' do
  title 'The firewall must be configured to inspect all inbound and outbound traffic at the application layer.'
  desc 'Application inspection enables the firewall to control traffic based on different parameters that exist within the packets such as enforcing application-specific message and field length. Inspection provides improved protection against application-based attacks by restricting the types of commands allowed for the applications. Application inspection all enforces conformance against published RFCs.

Some applications embed an IP address in the packet that needs to match the source address that is normally translated when it goes through the firewall. Enabling application inspection for a service that embeds IP addresses, the firewall translates embedded addresses and updates any checksum or other fields that are affected by the translation. Enabling application inspection for a service that uses dynamically assigned ports, the firewall monitors sessions to identify the dynamic port assignments, and permits data exchange on these ports for the duration of the specific session.'
  desc 'check', 'Review the firewall configuration to verify that inspection for applications deployed within the network is being performed on all interfaces.
If the firewall is not configured to inspect all inbound and outbound traffic at the application layer, this is a finding.'
  desc 'fix', 'Configure the firewall to inspect all inbound and outbound traffic at the application layer.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-24683r457848_chk'
  tag severity: 'medium'
  tag gid: 'V-223011'
  tag rid: 'SV-223011r604133_rule'
  tag stig_id: 'SRG-NET-000364-FW-000040'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-24672r457849_fix'
  tag 'documentable'
  tag legacy: ['SV-110207', 'V-101103']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
