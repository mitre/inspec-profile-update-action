control 'SV-217021' do
  title 'The Juniper router must be configured to have Gratuitous ARP disabled on all external interfaces.'
  desc 'A gratuitous ARP is an ARP broadcast in which the source and destination MAC addresses are the same. It is used to inform the network about a host IP address. A spoofed gratuitous ARP message can cause network mapping information to be stored incorrectly, causing network malfunction.'
  desc 'check', 'Review the configuration to determine if gratuitous ARP is disabled on all external interfaces. The following command should not be set to any interface: gratuitous-arp-reply

If gratuitous ARP is enabled on any external interface, this is a finding.'
  desc 'fix', 'Disable gratuitous ARP on all external interfaces using the following command.

[edit interfaces  ge-1/1/0 ]
delete gratuitous-arp-reply'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18250r296931_chk'
  tag severity: 'medium'
  tag gid: 'V-217021'
  tag rid: 'SV-217021r639663_rule'
  tag stig_id: 'JUNI-RT-000150'
  tag gtitle: 'SRG-NET-000362-RTR-000111'
  tag fix_id: 'F-18248r296932_fix'
  tag 'documentable'
  tag legacy: ['V-90827', 'SV-101037']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
