control 'SV-76699' do
  title 'The layer 2 switch must have all user-facing or untrusted ports configured as access switch ports.'
  desc "Double encapsulation can be initiated by an attacker who has access to a switch port belonging to the native VLAN of the trunk port. Knowing the victim's MAC address and with the victim attached to a different switch belonging to the same trunk group, thereby requiring the trunk link and frame tagging, the malicious user can begin the attack by sending frames with two sets of tags. The outer tag that will have the attacker's VLAN ID (probably the well-known and omnipresent default VLAN) is stripped off by the switch, and the inner tag that will have the victim's VLAN ID is used by the switch as the next hop and sent out the trunk port."
  desc 'check', 'Review the switch configurations and examine all user-facing or untrusted switch ports.

If any of the user-facing switch ports are configured as a trunk, this is a finding.'
  desc 'fix', 'Disable trunking on all user-facing or untrusted switch ports.'
  impact 0.5
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-63013r2_chk'
  tag severity: 'medium'
  tag gid: 'V-62209'
  tag rid: 'SV-76699r1_rule'
  tag stig_id: 'SRG-NET-000512-L2S-000011'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-68129r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
