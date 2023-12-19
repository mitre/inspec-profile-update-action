control 'SV-233330' do
  title 'Forescout switch module must only allow a maximum of one registered MAC address per access port. This is required for compliance with C2C Step 4.'
  desc "Limiting the number of registered MAC addresses on a switch access port can help prevent a CAM table overflow attack. This type of attack lets an attacker exploit the hardware and memory limitations of a switch. If there are enough entries stored in a CAM table before the expiration of other entries, no new entries can be accepted into the CAM table. An attacker will be able to flood the switch with mostly invalid MAC addresses until the CAM table's resources have been depleted. When there are no more resources, the switch has no choice but to flood all ports within the VLAN with all incoming traffic. This happens because the switch cannot find the switch port number for a corresponding MAC address within the CAM table, allowing the switch to become a hub and traffic to be monitored.

Some technologies are exempt from requiring a single MAC address per access port; however, restrictions still apply. VoIP or VTC endpoints may provide a PC port so a PC can be connected. Each of the devices will need to be statically assigned to each access port.

Hot-desking is where several people are assigned to work at the same desk at different times, each user with their own PC. In this case, a different MAC address needs to be permitted for each PC that is connecting to the LAN drop in the workspace. Additionally, this workspace could contain a single phone (and possibly desktop VTC endpoint) used by all assignees, and the PC port on it might be the connection for their laptop. In this case, it is best not to use sticky port security but to use a static mapping of authorized devices.

If this is not a teleworking remote location, this exemption does not apply."
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.

Review the switch configuration to verify each access port is configured for a single registered MAC address.

1. Log on to the Forescout UI.
2. Go to Tools >> Options >> Switch >> Permissions >> Advanced.
3. Verify the "Maximum connected endpoints per port" is set to "1".

If Forescout switch is not configured to permit a maximum of one registered MAC address per access port, this is a finding.'
  desc 'fix', 'Forescout has the ability to configure the amount of maximum connected endpoints per port. Allowing only one MAC address per port will break VOIP. Function is handled by the switch. 

1. Log on to the Forescout UI.
2. Go to Tools >> Options >> Switch >> Permissions >> Advanced.
3. Set the Maximum connected endpoints per port to one.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36525r811409_chk'
  tag severity: 'medium'
  tag gid: 'V-233330'
  tag rid: 'SV-233330r811410_rule'
  tag stig_id: 'FORE-NC-000240'
  tag gtitle: 'SRG-NET-000343-NAC-001480'
  tag fix_id: 'F-36490r803477_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
