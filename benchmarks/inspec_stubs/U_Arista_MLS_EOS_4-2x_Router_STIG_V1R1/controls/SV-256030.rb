control 'SV-256030' do
  title 'The Arista router must be configured to have gratuitous ARP disabled on all external interfaces.'
  desc 'A gratuitous ARP is an ARP broadcast in which the source and destination MAC addresses are the same. It is used to inform the network about a host IP address. A spoofed gratuitous ARP message can cause network mapping information to be stored incorrectly, causing network malfunction.'
  desc 'check', 'Review the configuration to determine if gratuitous ARP is disabled on all external interfaces.

By default, Arista router interfaces reject gratuitous ARP request packets. To verify the gratuitous ARP is disabled, execute the command "sh run int ethernet YY".

These commands enable/disable gratuitous ARP packet acceptance on.

Enable 

interface Ethernet 2
  arp gratuitous accept
  
Disable

interface Ethernet 2
  no arp gratuitous accept

If gratuitous ARP is enabled on any external interface, this is a finding.'
  desc 'fix', 'Disable gratuitous ARP on all external interfaces.

Disable

interface Ethernet 2
  no arp gratuitous accept'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59706r882430_chk'
  tag severity: 'medium'
  tag gid: 'V-256030'
  tag rid: 'SV-256030r882432_rule'
  tag stig_id: 'ARST-RT-000510'
  tag gtitle: 'SRG-NET-000362-RTR-000111'
  tag fix_id: 'F-59649r882431_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
