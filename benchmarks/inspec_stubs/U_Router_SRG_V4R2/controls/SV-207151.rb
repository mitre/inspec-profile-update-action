control 'SV-207151' do
  title 'The router must be configured to have Gratuitous ARP disabled on all external interfaces.'
  desc 'A gratuitous ARP is an ARP broadcast in which the source and destination MAC addresses are the same. It is used to inform the network about a host IP address. A spoofed gratuitous ARP message can cause network mapping information to be stored incorrectly, causing network malfunction.'
  desc 'check', 'Review the configuration to determine if gratuitous ARP is disabled on all external interfaces.

If gratuitous ARP is enabled on any external interface, this is a finding.'
  desc 'fix', 'Disable gratuitous ARP on all external interfaces.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7412r382436_chk'
  tag severity: 'medium'
  tag gid: 'V-207151'
  tag rid: 'SV-207151r604135_rule'
  tag stig_id: 'SRG-NET-000362-RTR-000111'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-7412r382437_fix'
  tag 'documentable'
  tag legacy: ['SV-92925', 'V-78219']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
