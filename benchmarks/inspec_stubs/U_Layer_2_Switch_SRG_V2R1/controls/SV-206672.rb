control 'SV-206672' do
  title 'The layer 2 switch must not have any switch ports assigned to the native VLAN.'
  desc 'Double encapsulation can be initiated by an attacker who has access to a switch port belonging to the native VLAN of the trunk port. Knowing the victim’s MAC address and with the victim attached to a different switch belonging to the same trunk group, thereby requiring the trunk link and frame tagging, the malicious user can begin the attack by sending frames with two sets of tags. The outer tag that will have the attacker’s VLAN ID (probably the well-known and omnipresent default VLAN) is stripped off by the switch, and the inner tag that will have the victim’s VLAN ID is used by the switch as the next hop and sent out the trunk port.'
  desc 'check', 'Review the switch configurations and examine all access switch ports. Verify that they do not belong to the native VLAN.

If any access switch ports have been assigned to the same VLAN ID as the native VLAN, this is a finding.'
  desc 'fix', 'Configure all access switch ports to a VLAN other than the native VLAN.'
  impact 0.3
  ref 'DPMS Target Layer 2 Switch'
  tag check_id: 'C-6930r298446_chk'
  tag severity: 'low'
  tag gid: 'V-206672'
  tag rid: 'SV-206672r385561_rule'
  tag stig_id: 'SRG-NET-000512-L2S-000013'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-6930r298447_fix'
  tag 'documentable'
  tag legacy: ['SV-76703', 'V-62213']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
