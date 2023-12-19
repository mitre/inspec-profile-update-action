control 'SV-251759' do
  title 'The NSX-T Tier-0 Gateway must be configured to have multicast disabled if not in use.'
  desc 'A compromised router introduces risk to the entire network infrastructure, as well as data resources that are accessible via the network. The perimeter defense has no oversight or control of attacks by malicious users within the network. Preventing network breaches from within is dependent on implementing a comprehensive defense-in-depth strategy, including securing each device connected to the network.

This is accomplished by following and implementing all security guidance applicable for each node type. A fundamental step in securing each router is to enable only the capabilities required for operation.'
  desc 'check', 'From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways.

For every Tier-0 Gateway, expand the Tier-0 Gateway, then expand Multicast to view the Multicast configuration.

If Multicast is enabled and not in use, this is a finding.'
  desc 'fix', 'To disable Multicast do the following:

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways and edit the target Tier-0 Gateway.

Expand Multicast, change from "Enabled" to "Disabled", and then click "Save".'
  impact 0.3
  ref 'DPMS Target VMware NSX-T Tier-0 Gateway RTR'
  tag check_id: 'C-55196r810159_chk'
  tag severity: 'low'
  tag gid: 'V-251759'
  tag rid: 'SV-251759r810161_rule'
  tag stig_id: 'T0RT-3X-000096'
  tag gtitle: 'SRG-NET-000131-RTR-000035'
  tag fix_id: 'F-55150r810160_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
