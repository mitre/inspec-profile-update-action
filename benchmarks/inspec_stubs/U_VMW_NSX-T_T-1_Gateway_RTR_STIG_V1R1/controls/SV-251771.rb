control 'SV-251771' do
  title 'The NSX-T Tier-1 Gateway must be configured to have the DHCP service disabled if not in use.'
  desc 'A compromised router introduces risk to the entire network infrastructure, as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network. This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'From the NSX-T Manager web interface, go to Networking >> Tier-1 Gateways.

For every Tier-1 Gateway expand the Tier-1 Gateway to view the DHCP configuration.

If a DHCP profile is configured and not in use, this is a finding.'
  desc 'fix', 'From the NSX-T Manager web interface, go to Networking >> Tier-1 Gateways and edit the target Tier-1 Gateway.

Click "Set DHCP Configuration", select "No Dynamic IP Address Allocation", click "Save", and then close "Editing".'
  impact 0.3
  ref 'DPMS Target VMware NSX-T Tier 1 Gateway RTR'
  tag check_id: 'C-55208r810211_chk'
  tag severity: 'low'
  tag gid: 'V-251771'
  tag rid: 'SV-251771r810213_rule'
  tag stig_id: 'T1RT-3X-000027'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag fix_id: 'F-55162r810212_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
