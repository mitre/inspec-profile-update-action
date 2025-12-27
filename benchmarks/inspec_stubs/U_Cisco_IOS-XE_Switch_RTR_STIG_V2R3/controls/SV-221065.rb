control 'SV-221065' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) switch must be configured to authenticate all received MSDP packets.'
  desc 'MSDP peering with customer network switches presents additional risks to the core, whether from a rogue or misconfigured MSDP-enabled switch. MSDP password authentication is used to validate each segment sent on the TCP connection between MSDP peers, protecting the MSDP session against the threat of spoofed packets being injected into the TCP connection stream.'
  desc 'check', 'Review the switch configuration to determine if received MSDP packets are authenticated.

ip msdp peer x.1.28.8 remote-as 8
ip msdp password peer x.1.28.8 xxxxxxxxxxxx

If the switch does not require MSDP authentication, this is a finding.'
  desc 'fix', 'Configure the switch to authenticate MSDP messages as shown in the following example:

SW2(config)#ip msdp password peer x.1.28.8 xxxxxxxxxxxx'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22780r408989_chk'
  tag severity: 'medium'
  tag gid: 'V-221065'
  tag rid: 'SV-221065r856428_rule'
  tag stig_id: 'CISC-RT-000910'
  tag gtitle: 'SRG-NET-000343-RTR-000002'
  tag fix_id: 'F-22769r408990_fix'
  tag 'documentable'
  tag legacy: ['SV-110951', 'V-101847']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
