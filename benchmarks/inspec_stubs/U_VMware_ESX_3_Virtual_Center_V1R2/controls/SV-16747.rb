control 'SV-16747' do
  title 'Virtual switch port group is configured to VLAN 1001 to 1024.'
  desc 'The VLAN ID restricts port group traffic to a logical Ethernet segment within the physical network. Port groups may have a VLAN ID of 0 to 4095. VLAN ID values of 1 to 4094 place the virtual switch in VST mode. However VLAN 1 will not be enabled for port groups since ESX Server does not support virtual switch port groups configured to VLAN 1. VLAN 1001 through 1024 are Cisco reserved VLANs. VLANs 1, 1001 to 1024, and 4095 will be not be used for virtual switch port groups since they may cause an unexpected operation.'
  desc 'check', '1. Log into VirualCenter with the VI Client and select the ESX server from the inventory panel.
2. Click the Configuration tab and click Networking.
    Virtual switches are presented in a layout that shows an overview and details.
3. On the right side of the window, click Properties for a network.
4. Click the Ports tab.
5. In the Properties dialog box for the port group, click the General tab to check the VLAN ID.  If the VLAN ID is set to 1001 to 1024, this is a finding.'
  desc 'fix', 'Do not configure virtual switch VLAN IDs s to be VLAN 1, 1001-1024, and 4095.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16050r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15808'
  tag rid: 'SV-16747r1_rule'
  tag stig_id: 'ESX0190'
  tag gtitle: 'Virtual switch port group is set to VLAN 1001-1024'
  tag fix_id: 'F-15752r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
