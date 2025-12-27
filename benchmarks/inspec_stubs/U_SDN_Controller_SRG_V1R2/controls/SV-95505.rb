control 'SV-95505' do
  title 'The SDN Controller must be configured to notify the forwarding device to either drop the packet or make an entry in the flow table for a received packet that does not match any flow table entries.'
  desc 'Reactive flow setup occurs when the SDN-aware switch receives a packet that does not match the flow table entries and hence the switch has to send the packet to the controller for processing. Once the controller decides how to process the flow that information is cached on the SDN-aware switch, and the SDN controller determines how long to keep the cache alive. In order to prevent packets from being dropped as a result of no flow table entry, it is imperative that the SDN Controller is configured to enable reactive flow setup.'
  desc 'check', 'Review the SDN controller configuration to determine if it is configured to enable reactive flow setup. 

If the SDN Controller is not configured to notify the forwarding device to either drop the packet or make an entry in the flow table for a received packet that does not match any flow table entries, this is a finding.'
  desc 'fix', 'Configure the SDN controller to enable reactive flow setup so that the controller will notify a forwarding device to either drop the packet or make an entry in the flow table for a received packet that does not match any flow table entries.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80531r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80795'
  tag rid: 'SV-95505r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001055'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87649r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
