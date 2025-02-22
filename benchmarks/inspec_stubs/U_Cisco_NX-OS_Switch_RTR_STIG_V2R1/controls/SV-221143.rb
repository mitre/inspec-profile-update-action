control 'SV-221143' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) switch must be configured to authenticate all received MSDP packets.'
  desc 'MSDP peering with customer network switches presents additional risks to the core, whether from a rogue or misconfigured MSDP-enabled switch. MSDP password authentication is used to validate each segment sent on the TCP connection between MSDP peers, protecting the MSDP session against the threat of spoofed packets being injected into the TCP connection stream.'
  desc 'check', 'Review the switch configuration to determine if received MSDP packets are authenticated.

ip msdp peer x.1.28.2 remote-as nn
ip msdp password peer x.1.28.2 xxxxxxxxxxxx

ip msdp peer x.1.28.2 connect-source Ethernet2/3 remote-as 8
ip msdp password x.1.28.2 3 3ec66c90c104ad13

If the switch does not require MSDP authentication, this is a finding.'
  desc 'fix', 'Configure the switch to authenticate MSDP messages as shown in the following example:

SW1(config)# ip msdp password x.1.28.2 xxxxxxxxxxxx'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22858r409918_chk'
  tag severity: 'medium'
  tag gid: 'V-221143'
  tag rid: 'SV-221143r622190_rule'
  tag stig_id: 'CISC-RT-000910'
  tag gtitle: 'SRG-NET-000343-RTR-000002'
  tag fix_id: 'F-22847r409919_fix'
  tag 'documentable'
  tag legacy: ['SV-111253', 'V-102297']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
