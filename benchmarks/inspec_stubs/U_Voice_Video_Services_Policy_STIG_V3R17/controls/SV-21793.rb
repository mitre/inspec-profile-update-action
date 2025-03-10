control 'SV-21793' do
  title 'The access switch must only allow a maximum of one registered MAC address per access port, except when the Voice Video Endpoint has an enabled PC port.'
  desc 'Limiting the number of registered MAC addresses on a switch access port can help prevent a CAM table overflow attack. This type of attack lets an attacker exploit the hardware and memory limitations of a switch. If there are enough entries stored in a CAM table before the expiration of other entries, no new entries can be accepted into the CAM table. An attacker will be able to flood the switch with mostly invalid MAC addresses until the CAM table’s resources have been depleted. When there are no more resources, the switch has no choice but to flood all ports within the VLAN with all incoming traffic. This happens because the switch cannot find the switch port number for a corresponding MAC address within the CAM table, allowing the switch to become a hub and traffic to be monitored.

Many Voice Video Endpoints provide an extra Ethernet port called a PC port that permits the endpoint and another device to share the same LAN drop. A Voice Video Endpoint can be added to a LAN without having to run additional cable or activate additional LAN drops; allowing a single LAN drop to support both the PC and the Voice Video Endpoint.

Another initiative where a single LAN drop is shared is hot desking, where several people are assigned to work at the same desk at different times, each with their own laptop computer. In this case, a different MAC address needs to be permitted for each laptop that is supposed to connect to the LAN drop in the workspace. Additionally, this workspace could contain a single phone used by all assignees and the PC port on it might be the connection for their laptop.'
  desc 'check', 'Review the site documentation to confirm the access switch only allows a maximum of one registered MAC address per access port, except when the Voice Video Endpoint has an enabled PC port.

Verify that each access switch port supporting Voice Video Endpoints is configured supporting 802.1x. The 802.1x configuration may be set to be single-host (the default), multi-domain (for Voice Video Endpoints with a PC port), or multi-auth (each PC connected to a hub must authenticate). However, host mode as multi-host, which allows only one has to authenticate while other PCs connected to the same hub can piggyback is not permitted.

If the 802.1x access port is configured host mode as multi-host, this is a finding.

If the 802.1x access port is configured single-host (the default), multi-domain (for Voice Video Endpoints with a PC port), or multi-auth (each PC connected to a hub must authenticate), this is not a finding.

If the static access port is connected to a Voice Video Endpoint with an enabled PC port, this is a finding.

If the static access port is connected to a Voice Video Endpoint with more than one registered MAC address, this is a finding.'
  desc 'fix', 'Implement and document the access switch only allows a maximum of one registered MAC address per access port, except when the Voice Video Endpoint has an enabled PC port.

When 802.1x is implemented on the access switch port, the configuration may be set to be single-host (the default), multi-domain (for Voice Video Endpoints with a PC port), or multi-auth (each PC connected to a hub must authenticate). However, host mode as multi-host, which allows only one, has to authenticate while other PCs connected to the same hub can piggyback is not permitted.

When static MAC addresses are used, configure the attached Voice Video Endpoint with the PC port disabled. See the Voice Video Endpoint SRG for additional information.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-24003r4_chk'
  tag severity: 'medium'
  tag gid: 'V-19652'
  tag rid: 'SV-21793r4_rule'
  tag stig_id: 'VVoIP 5300'
  tag gtitle: 'VVoIP 5300'
  tag fix_id: 'F-20356r4_fix'
  tag 'documentable'
end
