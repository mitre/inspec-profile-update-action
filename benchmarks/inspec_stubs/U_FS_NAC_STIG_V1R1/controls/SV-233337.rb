control 'SV-233337' do
  title 'Forescout must perform continuous detection and tracking of endpoint devices attached to the network.'
  desc "Continuous scanning capabilities on the NAC provide visibility of devices that are connected to the switch ports. The NAC continuously scans networks and monitors the activity of managed and unmanaged devices, which can be personally owned or rogue endpoints. Because many of today's small devices do not include agents, an agentless discovery is often combined to cover more types of equipment."
  desc 'check', 'Verify the NAC performs continuous detection and tracking of endpoint devices attached to the network.

1. Log on to the Forescout UI.
2. Go to Tools >> Options >> Appliance >> IP Assignment.
3. Check that all IP addresses that should be managed are within the IP Assignments as required by the SSP.

If the NAC does not perform continuous detection and tracking of endpoint devices attached to the network, this is a finding.'
  desc 'fix', 'Log on to the Forescout UI.

1. Go to Tools >> Options >> Appliance >> IP Assignment.
2. Enter all IP addresses to be managed in the IP Assignment to enable the continuous monitoring capabilities of Forescout.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36532r605714_chk'
  tag severity: 'medium'
  tag gid: 'V-233337'
  tag rid: 'SV-233337r611394_rule'
  tag stig_id: 'FORE-NC-000440'
  tag gtitle: 'SRG-NET-000512-NAC-002310'
  tag fix_id: 'F-36497r605715_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
