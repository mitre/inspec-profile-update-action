control 'SV-206670' do
  title 'The layer 2 switch must have all user-facing or untrusted ports configured as access switch ports.'
  desc "Double encapsulation can be initiated by an attacker who has access to a switch port belonging to the native VLAN of the trunk port. Knowing the victim's MAC address and with the victim attached to a different switch belonging to the same trunk group, thereby requiring the trunk link and frame tagging, the malicious user can begin the attack by sending frames with two sets of tags. The outer tag that will have the attacker's VLAN ID (probably the well-known and omnipresent default VLAN) is stripped off by the switch, and the inner tag that will have the victim's VLAN ID is used by the switch as the next hop and sent out the trunk port."
  desc 'check', 'Review the switch configurations and examine all user-facing or untrusted switch ports.

If any of the user-facing switch ports are configured as a trunk, this is a finding.'
  desc 'fix', 'Disable trunking on all user-facing or untrusted switch ports.'
  impact 0.5
  ref 'DPMS Target Layer 2 Switch'
  tag check_id: 'C-6928r298440_chk'
  tag severity: 'medium'
  tag gid: 'V-206670'
  tag rid: 'SV-206670r385561_rule'
  tag stig_id: 'SRG-NET-000512-L2S-000011'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-6928r298441_fix'
  tag 'documentable'
  tag legacy: ['SV-76699', 'V-62209']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
