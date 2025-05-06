control 'SV-21792' do
  title 'When 802.1x is implemented and the voice video endpoint PC ports are disabled, the network access switch port must be configured to support a disabled PC port by configuring PC port traffic to the unused VLAN.'
  desc 'A voice video endpoint that provides a PC port typically breaks 802.1x LAN access control mechanisms. The cause is the network access switch port is enabled or authorized (and configured) when the voice video endpoint authenticates to the network and is authorized to operate. This may permit whatever is connected to the PC port to have access to the LAN even if it is not authorized or uses 802.1x. Therefore, the practice of daisy chaining devices on a single LAN drop protected by 802.1x must be prohibited unless certain mitigating circumstances exist or are configured. 

In the event a PC port is provided, the mitigation is to disable the port. However, the 802.1x implementation must install the configuration on the network access switch port required to support a voice video endpoint with a disabled PC port. This means the required configuration for the network access switch ports is to configure the appropriate VLAN for the voice video traffic and configure the unused VLAN for the disabled PC port.'
  desc 'check', 'If the voice video endpoints do not contain a PC port, this is not applicable.

Review site documentation to confirm that when 802.1x is implemented and the voice video endpoint PC ports are disabled, the network access switch port is configured to support a disabled PC port by configuring PC port traffic to the unused VLAN. 

If 802.1x is implemented, the voice video endpoint PC ports are disabled, and the network access switch port is not configured to support a disabled PC port by configuring PC port traffic to the unused VLAN, this is a finding.

The voice video endpoint network access switch port normally is configured with a VVoIP VLAN for the VVoIP traffic. This is IAW and supports the NI STIG requirement NET1435.'
  desc 'fix', 'Implement and document that when 802.1x is implemented and the voice video endpoint PC ports are disabled, the network access switch port is configured to support a disabled PC port by sending PC port traffic to the unused VLAN.

Do not statically assign the switch port to the voice video VLAN.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-24000r3_chk'
  tag severity: 'medium'
  tag gid: 'V-19651'
  tag rid: 'SV-21792r3_rule'
  tag stig_id: 'VVoIP 5320'
  tag gtitle: 'VVoIP 5320'
  tag fix_id: 'F-20355r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
