control 'SV-243087' do
  title 'The vCenter Server must not configure VLAN Trunking unless Virtual Guest Tagging (VGT) is required and authorized.'
  desc 'When a port group is set to VLAN Trunking, the vSwitch passes all network frames in the specified range to the attached VMs without modifying the VLAN tags. In vSphere, this is referred to as Virtual Guest Tagging (VGT). 

The VM must process the VLAN information itself via an 802.1Q driver in the OS. VLAN Trunking must only be implemented if the attached VMs have been specifically authorized and are capable of managing VLAN tags themselves. 

If VLAN Trunking is enabled inappropriately, it may cause denial of service or allow a VM to interact with traffic on an unauthorized VLAN.'
  desc 'check', 'From the vSphere Client, go to Networking >> select a distributed switch >> select a distributed port group >> Configure >> Settings >> Policies. 

Review the port group "VLAN Type" and "VLAN trunk range", if present.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-VDPortgroup | Where {$_.ExtensionData.Config.Uplink -ne "True"} | select Name,VlanConfiguration

If any port group is configured with "VLAN Trunk" and is not documented as a needed exception (such as NSX appliances), this is a finding.

If any port group is authorized to be configured with "VLAN trunking" but is not configured with the most limited range necessary, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Networking >> select a distributed switch >> select a distributed port group >> Configure >> Settings >> Policies. 

Click "Edit". 

Click the "VLAN" tab.

If "VLAN trunking" is not authorized, remove it by setting "VLAN type" to "VLAN" and configure an appropriate VLAN ID. Click "OK".

If "VLAN trunking" is authorized but the range is too broad, modify the range in the "VLAN trunk range" field to the minimum necessary and authorized range. An example range would be "1,3-5,8". Click "OK".

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command to configure trunking:

Get-VDPortgroup "Portgroup Name" | Set-VDVlanConfiguration -VlanTrunkRange "<VLAN Range(s) comma separated>"

or 

Run this command to configure a single VLAN ID:

Get-VDPortgroup "Portgroup Name" | Set-VDVlanConfiguration -VlanId "<New VLAN#>"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46362r719502_chk'
  tag severity: 'medium'
  tag gid: 'V-243087'
  tag rid: 'SV-243087r719504_rule'
  tag stig_id: 'VCTR-67-000019'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-46319r719503_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
